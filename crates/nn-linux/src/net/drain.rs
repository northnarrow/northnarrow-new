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
//! Both records emit through the same `crate::sensors::bus::BusSender` the
//! sensor multiplexer feeds the main loop with, so the rule engine
//! sees `Event::NetFlow` / `Event::NetListener` items via the
//! existing `process_event` path (`main::process_event` already
//! has match arms for both — added in N6).
//!
//! External audit NET-019: the rows are written as they come and made
//! durable together, by one fsync at most every
//! [`NETFLOW_SYNC_INTERVAL`] (a group commit; one fsync per row before,
//! which a connect/close loop turned into ring drops). A crash of the
//! host can lose the rows of the last interval, or tear the last one,
//! which the next open cuts and attests; the agent stopping or crashing
//! loses nothing (the rows are in the page cache). The rows handed to
//! the rules are paced per uid ([`crate::net::limiter`]); a row held
//! back is still written, flagged `decision_engine_skipped`.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use aya::maps::{ring_buf::RingBuf, MapData};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use common::wire::{NetFlowCloseRaw, NetListenRaw};
use nn_model::telemetry::{NetFlowEvent, NetListenerEvent};
use nn_model::Event;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};
use crate::net::dns_cache::DnsCache;
use crate::net::flow_tracker::{FlowTracker, SnapshotPolicy, TcpCloseInfo, UdpSendInfo};
use crate::net::limiter::RuleGate;

/// External audit NET-019: the longest a netflow or listener row waits for
/// its fsync (the group commit's period; module docs).
pub const NETFLOW_SYNC_INTERVAL: Duration = Duration::from_millis(100);

/// Default on-disk location of the chained NetListener log
/// (design §6.4). Mirrors `admin_socket::DEFAULT_NETFLOW_JSONL_PATH`
/// — the listeners log is the second of the two Tappa 10
/// LSM-protected state files.
pub const DEFAULT_NETFLOW_LISTENERS_JSONL_PATH: &str =
    "/var/lib/northnarrow/netflow_listeners.jsonl";

/// Permission bits applied to the netflow + netflow_listeners
/// logs at create time: root only (external audit EVD-019,
/// [`crate::chainlog::STATE_LOG_FILE_MODE`]); LSM PROTECTED_INODES +
/// PROTECTED_PIDS exemption enforces append-only against other root
/// callers.
const NET_LOG_FILE_MODE: u32 = crate::chainlog::STATE_LOG_FILE_MODE;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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

/// BUG-026 migration — the `netflow.jsonl` DATA payload: every
/// [`NetFlowEntry`] field EXCEPT the chain framing (`prev_hash` /
/// `entry_hash` / `agent_sig`), in the SAME declaration order. A
/// [`crate::chainlog::ChainLine<NetFlowPayload>`] with `fmt_ver = None`
/// therefore serialises BYTE-FOR-BYTE identically to a legacy v1
/// `NetFlowEntry`, so an existing on-disk `netflow.jsonl` still verifies
/// under the rotation-aware reader (proven by
/// `bug026_legacy_v1_netflow_line_still_verifies`). The one field the
/// legacy row lacks, `decision_engine_skipped`, is absent when `false`
/// (`skip_serializing_if`), so the mirror stays exact for every row
/// written before it and every row the rules evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFlowPayload {
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
    /// External audit NET-019 (design §6.5, lock-in Q4): the row was held
    /// back from the rules by the per-uid pacing (`net::limiter`) and not
    /// evaluated. Written only when `true`; a row without it was handed
    /// to the rules.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub decision_engine_skipped: bool,
}

/// External audit EVD-008 (lab PR 204): the netflow log's name in its v3
/// pre-images.
impl crate::chainlog::ChainPayload for NetFlowPayload {
    const KIND: &'static str = "netflow";
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
    inner: crate::chainlog::RotatingChainLog<NetFlowPayload>,
    agent_id: [u8; 16],
    /// External audit NET-019: when the last group commit ran.
    last_sync: Instant,
}

impl NetFlowDb {
    pub fn open(
        path: &Path,
        key: AgentSigningKey,
        agent_id: [u8; 16],
        protection: std::sync::Arc<dyn crate::chainlog::ProtectionManager>,
        cfg: crate::chainlog::RotationConfig,
    ) -> Result<Self> {
        let inner =
            crate::chainlog::RotatingChainLog::<NetFlowPayload>::open(path, key, cfg, protection)?;
        Ok(Self {
            inner,
            agent_id,
            last_sync: Instant::now(),
        })
    }

    /// Append one closed-flow row as a signed chainlog data line
    /// (rotating at the size cap). Returns the new line's `entry_hash`.
    /// External audit NET-019: the row is written, not fsynced —
    /// [`Self::sync_if_due`] commits the rows of the last
    /// [`NETFLOW_SYNC_INTERVAL`] together. `skipped`: the row was held
    /// back from the rules (`decision_engine_skipped`).
    pub fn append(&mut self, ev: &NetFlowEvent, skipped: bool) -> Result<String> {
        let payload = NetFlowPayload {
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
            decision_engine_skipped: skipped,
        };
        self.inner.append_deferred(payload)
    }

    /// External audit NET-019: fsync the rows written since the last
    /// commit once [`NETFLOW_SYNC_INTERVAL`] has passed since it. `true`
    /// when an fsync ran. A failed one is retried after the interval.
    pub fn sync_if_due(&mut self, now: Instant) -> Result<bool> {
        if !self.inner.has_unsynced()
            || now.saturating_duration_since(self.last_sync) < NETFLOW_SYNC_INTERVAL
        {
            return Ok(false);
        }
        self.last_sync = now;
        self.inner.sync().map(|()| true)
    }

    /// fsyncs of the log by this writer (tests).
    pub fn fsyncs(&self) -> u64 {
        self.inner.fsyncs()
    }

    pub fn last_hash(&self) -> &str {
        self.inner.last_hash()
    }
}

/// Append-only chained writer for `netflow_listeners.jsonl`. Same
/// shape as [`NetFlowDb`].
pub struct NetListenerDb {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
    tail_repair: Option<crate::chainlog::TailRepair>,
    /// External audit NET-019: rows written since the last fsync, and
    /// when it ran (the same group commit as `netflow.jsonl`).
    unsynced: bool,
    last_sync: Instant,
}

impl NetListenerDb {
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        // External audit NET-003: a torn last write used to make every
        // later open fail, and the network drain never ran again.
        let tail_repair =
            crate::chainlog::repair_torn_tail::<crate::chain_host_linux::LinuxHost>(path, |l| {
                serde_json::from_slice::<NetListenerEntry>(l).is_ok()
            })?;
        let last_hash = read_tail_hash_listener(path)?;
        Ok(Self {
            // review 44: appends go through a directory fd taken now
            path: crate::anchored::anchor(path),
            key,
            agent_id,
            last_hash,
            tail_repair,
            unsynced: false,
            last_sync: Instant::now(),
        })
    }

    /// The torn tail repaired at open, for the caller to attest once.
    pub fn take_tail_repair(&mut self) -> Option<crate::chainlog::TailRepair> {
        self.tail_repair.take()
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
        // External audit NET-019: committed by `sync_if_due`.
        self.unsynced = true;
        self.last_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    /// As [`NetFlowDb::sync_if_due`].
    pub fn sync_if_due(&mut self, now: Instant) -> Result<bool> {
        if !self.unsynced || now.saturating_duration_since(self.last_sync) < NETFLOW_SYNC_INTERVAL {
            return Ok(false);
        }
        self.last_sync = now;
        let f = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {} for fsync", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.unsynced = false;
        Ok(true)
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
    udp_rb: RingBuf<MapData>,
    flow_tracker: Arc<Mutex<FlowTracker>>,
    dns_cache: Arc<DnsCache>,
    // Lab PR 218 (external review P0 C-14): `None` when the netflow log
    // cannot be opened — the drain runs all the same, the flows reach the
    // rules unpersisted (the drain used to stay off for the whole boot:
    // TCP, UDP and listeners blind).
    netflow_db: Option<Arc<Mutex<NetFlowDb>>>,
    // External audit NET-003: `None` when the listener log cannot be
    // opened — listener events still reach the rules, unpersisted.
    listener_db: Option<Arc<Mutex<NetListenerDb>>>,
    // External audit NETR-008: names the sender's image on a UDP record.
    lineage: crate::posture::lineage::AuthSessionTracker,
    // External audit NET-019: which rows reach the rules.
    mut gate: RuleGate,
    // Lab PR 224 (CM-02 b): which open flows are re-judged, how often.
    snapshot: SnapshotPolicy,
    event_tx: crate::sensors::bus::BusSender,
) -> std::io::Result<()> {
    let mut close_fd = crate::async_fd::register(close_rb)?;
    let mut listen_fd = crate::async_fd::register(listen_rb)?;
    // Review 73: the UDP flow records have their own ring, so a UDP flood
    // cannot erase the TCP closes; they are processed the same way.
    let mut udp_fd = crate::async_fd::register(udp_rb)?;
    // External audit NET-019: commits the rows of a quiet period too.
    let mut commit_tick = tokio::time::interval(NETFLOW_SYNC_INTERVAL);
    commit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Lab PR 224 (CM-02 b): the open-flow snapshots, checked every tick
    // (each flow is due once per interval).
    let mut snapshot_tick = tokio::time::interval(snapshot_tick_period(&snapshot));
    snapshot_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Lab PR 229: the records of one readiness, read before any is
    // processed, so that one wait for the DNS pump serves them all.
    let mut batch: Vec<NetFlowCloseRaw> = Vec::new();
    loop {
        tokio::select! {
            _ = commit_tick.tick() => {
                group_commit(netflow_db.as_ref(), listener_db.as_ref());
            }
            _ = snapshot_tick.tick() => {
                let rows = due_snapshot_rows(
                    &flow_tracker,
                    &dns_cache,
                    &lineage,
                    &snapshot,
                    monotonic_ns(),
                );
                for row in rows {
                    crate::net::flow_tracker::note_snapshot_sent();
                    if event_tx.send(Event::NetFlow(row)).await.is_err() {
                        return Ok(());
                    }
                }
            }
            r = udp_fd.readable_mut() => {
                let mut guard = r?;
                let inner = guard.get_inner_mut();
                let mut drained = 0u32;
                while let Some(item) = inner.next() {
                    drained += 1;
                    match bytemuck::try_from_bytes::<NetFlowCloseRaw>(item.as_ref()) {
                        Ok(raw) => batch.push(*raw),
                        // refused (and said so) by the record's processing
                        Err(_) => {
                            process_close_record(
                                item.as_ref(),
                                &flow_tracker,
                                &dns_cache,
                                netflow_db.as_ref(),
                                &lineage,
                                &mut gate,
                                &event_tx,
                            )
                            .await
                        }
                    }
                }
                guard.clear_ready();
                attribution_barrier(&batch, &dns_cache).await;
                for raw in batch.drain(..) {
                    process_close_record(
                        bytemuck::bytes_of(&raw),
                        &flow_tracker,
                        &dns_cache,
                        netflow_db.as_ref(),
                        &lineage,
                        &mut gate,
                        &event_tx,
                    )
                    .await;
                    group_commit(netflow_db.as_ref(), listener_db.as_ref());
                }
                if drained == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            r = close_fd.readable_mut() => {
                let mut guard = r?;
                let inner = guard.get_inner_mut();
                let mut drained = 0u32;
                while let Some(item) = inner.next() {
                    drained += 1;
                    match bytemuck::try_from_bytes::<NetFlowCloseRaw>(item.as_ref()) {
                        Ok(raw) => batch.push(*raw),
                        // refused (and said so) by the record's processing
                        Err(_) => {
                            process_close_record(
                                item.as_ref(),
                                &flow_tracker,
                                &dns_cache,
                                netflow_db.as_ref(),
                                &lineage,
                                &mut gate,
                                &event_tx,
                            )
                            .await
                        }
                    }
                }
                guard.clear_ready();
                attribution_barrier(&batch, &dns_cache).await;
                // Lab PR 246: each close after its connect, on the bus too.
                connect_barrier(&batch, &flow_tracker).await;
                for raw in batch.drain(..) {
                    process_close_record(
                        bytemuck::bytes_of(&raw),
                        &flow_tracker,
                        &dns_cache,
                        netflow_db.as_ref(),
                        &lineage,
                        &mut gate,
                        &event_tx,
                    )
                    .await;
                    group_commit(netflow_db.as_ref(), listener_db.as_ref());
                }
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
                    process_listen_record(item.as_ref(), listener_db.as_ref(), &event_tx).await;
                    group_commit(netflow_db.as_ref(), listener_db.as_ref());
                }
                guard.clear_ready();
                if drained == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    }
}

/// Lab PR 229: wait until the DNS pump has read the queries made before
/// the newest record of `batch` (`DnsIngest`), so that each record's DNS
/// attribution finds its process's query. A close read before the pump had
/// read the query of the same process attributed no name — the CI flake of
/// `net_outbound_connect_records_flow_with_dns_attribution`.
async fn attribution_barrier(batch: &[NetFlowCloseRaw], dns_cache: &DnsCache) {
    if let Some(ts) = batch.iter().map(|r| r.timestamp_ns).max() {
        dns_cache.ingest().caught_up(ts).await;
    }
}

/// Lab PR 224: how often the drain looks for due snapshots — every 10 s, or
/// the interval when shorter (at least 1 s).
fn snapshot_tick_period(policy: &SnapshotPolicy) -> Duration {
    Duration::from_nanos(policy.interval_ns.clamp(1_000_000_000, 10_000_000_000))
}

/// CLOCK_MONOTONIC in ns: `bpf_ktime_get_ns`'s clock, the flows' clock.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Lab PR 224 (CM-02 b): the snapshots due at `now_ns`, for the rules.
/// A flow whose process is gone, or whose pid another process holds now
/// (it started after the connect), is not handed out: its socket may live
/// on in a child, but nothing names it. The image is read again — the
/// process may have executed another since its connect — and so is the
/// DNS name.
pub(crate) fn due_snapshot_rows(
    flow_tracker: &Mutex<FlowTracker>,
    dns_cache: &DnsCache,
    lineage: &crate::posture::lineage::AuthSessionTracker,
    policy: &SnapshotPolicy,
    now_ns: u64,
) -> Vec<NetFlowEvent> {
    let batch = flow_tracker.lock().due_snapshots(now_ns, policy);
    if batch.deferred > 0 {
        debug!(
            target: "net.drain",
            deferred = batch.deferred,
            max = policy.max_per_tick,
            "open-flow snapshots deferred to a later tick (per-tick bound)"
        );
    }
    let mut out = Vec::with_capacity(batch.flows.len());
    for mut row in batch.flows {
        match lineage.start_floor_ns(row.pid) {
            None => continue,
            Some(floor) if floor > row.start_ns => continue,
            Some(_) => {}
        }
        if let Some(image) = lineage.image_path(row.pid) {
            row.exe = Some(image);
        }
        row.resolved_hostname =
            dns_cache.lookup_for_connect(row.pid, row.start_ns, row.proc_start_ns);
        out.push(row);
    }
    out
}

/// External audit NET-019: one fsync for the netflow rows, and one for the
/// listener rows, written since their last commit, at most every
/// [`NETFLOW_SYNC_INTERVAL`]. Called after each record and on a timer, so
/// no row waits longer than the interval (plus one record's processing).
fn group_commit(
    netflow_db: Option<&Arc<Mutex<NetFlowDb>>>,
    listener_db: Option<&Arc<Mutex<NetListenerDb>>>,
) {
    let now = Instant::now();
    if let Some(db) = netflow_db {
        if let Err(e) = db.lock().sync_if_due(now) {
            warn!(error = %format!("{e:#}"), "netflow log: group commit (fsync) failed; retried");
        }
    }
    if let Some(db) = listener_db {
        if let Err(e) = db.lock().sync_if_due(now) {
            warn!(error = %format!("{e:#}"), "netflow_listeners log: group commit (fsync) failed; retried");
        }
    }
}

/// External audit EBPF-019: the half of a kernel flow correlator that may
/// be logged — the connect's `start_ns` (bytes 0..8, little-endian,
/// `FlowTracker::corr_id`). Bytes 8..16 are the socket's kernel address,
/// which nothing outside the agent sees.
fn corr_start_ns(corr: &[u8; 16]) -> u64 {
    FlowTracker::corr_start_ns(corr)
}

/// Lab PR 246: how long a TCP close waits for its connect to be on the bus,
/// counted from the connect's kernel time (its correlator's): the connect
/// pump may itself wait [`crate::net::dns_cache::INGEST_WAIT`] for the DNS
/// pump before it sends a connect. A close whose connect is older than
/// this (connected before the agent started, or long ago) waits for
/// nothing.
pub const CONNECT_WAIT: Duration = Duration::from_millis(500);

/// Lab PR 246: hold the TCP closes of `batch` until the connect pump has
/// put their connects on the bus ([`FlowTracker::close_may_proceed`]), at
/// most [`CONNECT_WAIT`] from each connect's time. The connect and the
/// close come on two rings, read by two tasks: a close resolved first was
/// synthesised (the connect's destination lost — a refused connect showed
/// port 0) and reached the rules before its `Event::TcpConnect`, so the
/// close of a network canary trip's own connection was judged before the
/// trip that owns it, or as an egress after it (NN-L-CHAIN-003 on the
/// trip's own connection, the KVM failure of 27/10/2026). Past the wait
/// the close goes on as before (synthesised under its connect's time).
pub(crate) async fn connect_barrier(batch: &[NetFlowCloseRaw], flow_tracker: &Mutex<FlowTracker>) {
    let announced = flow_tracker.lock().announcements();
    for raw in batch.iter().filter(|r| r.proto == IPPROTO_TCP) {
        let connect_ns = corr_start_ns(&raw.flow_id);
        let age = Duration::from_nanos(monotonic_ns().saturating_sub(connect_ns));
        let Some(left) = CONNECT_WAIT.checked_sub(age) else {
            continue;
        };
        let deadline = tokio::time::Instant::now() + left;
        loop {
            let notified = announced.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if flow_tracker.lock().close_may_proceed(&raw.flow_id) {
                break;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                debug!(
                    target: "net.drain",
                    pid = raw.pid,
                    corr_start_ns = connect_ns,
                    "net drain: a TCP close's connect was not on the bus within the wait — \
                     the close goes on (its row synthesised if the connect is still unread)"
                );
                break;
            }
        }
    }
}

async fn process_close_record(
    bytes: &[u8],
    flow_tracker: &Arc<Mutex<FlowTracker>>,
    dns_cache: &Arc<DnsCache>,
    netflow_db: Option<&Arc<Mutex<NetFlowDb>>>,
    lineage: &crate::posture::lineage::AuthSessionTracker,
    gate: &mut RuleGate,
    event_tx: &crate::sensors::bus::BusSender,
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
    // External audit NET-020 (3) (lab PR 207): one decoding of the kernel's
    // comm for every branch — up to the first NUL, as the connect, UDP and
    // listener paths read it — so the same bytes give the same name to the
    // row, the journal and the comm allowlist.
    let comm = comm_to_string(&raw.comm);
    let mut event = match raw.proto {
        IPPROTO_TCP => {
            let info = TcpCloseInfo {
                end_ns: raw.timestamp_ns,
                corr_id: raw.flow_id,
                src_addr: decode_addr(raw.family, raw.src_addr),
                src_port: raw.src_port,
                bytes_sent: raw.bytes_sent,
                bytes_recv: raw.bytes_recv,
                close_reason: raw.close_reason,
                family: raw.family,
                dst_addr: decode_addr(raw.family, raw.dst_addr),
                dst_port: raw.dst_port,
                pid: raw.pid,
                uid: raw.uid,
                comm,
            };
            let closed = flow_tracker.lock().on_tcp_close(&info);
            match closed {
                Some(mut e) => {
                    // External audit NET-012: a row the close synthesised
                    // (its connect not seen yet, or evicted at capacity)
                    // names the image as a UDP row does; read after the
                    // tracker's lock.
                    if e.exe.is_none() {
                        e.exe = lineage.image_path(e.pid);
                    }
                    e
                }
                None => {
                    // Orphan close. Two very different cases:
                    //  * corr_id all-zero = the kernel-side FLOW_SOCK_MAP
                    //    lookup missed. EXPECTED for every passive socket
                    //    (listeners and accept()ed peers never pass the
                    //    connect kprobe) and for connects that predate the
                    //    agent — debug-level, or a busy server would log a
                    //    WARN per inbound connection.
                    //  * corr_id present = the connect kprobe recorded the
                    //    flow but userland has no pending entry (eviction
                    //    at capacity, ringbuf drop, drain restart). That is a
                    //    genuine gap in netflow.jsonl: WARN with the
                    //    5-tuple (review entry 18).
                    let kernel_lookup_miss = raw.flow_id == [0u8; 16];
                    let comm = &info.comm;
                    let dst = format!("{}:{}", decode_addr(raw.family, raw.dst_addr), raw.dst_port);
                    let src = format!("{}:{}", info.src_addr, info.src_port);
                    if kernel_lookup_miss {
                        debug!(
                            target: "net.drain",
                            pid = raw.pid,
                            comm = %nn_model::log_escape::Escaped(comm),
                            src = %src,
                            dst = %dst,
                            "net drain: TCP close without a connect-side flow (passive or pre-agent socket) — not recorded"
                        );
                    } else {
                        // External audit EBPF-019: the kernel correlator is
                        // the connect's timestamp then the socket's kernel
                        // address (bytes 8..16); only the timestamp half
                        // reaches the journal, which the `adm` and
                        // `systemd-journal` groups read.
                        warn!(
                            target: "net.drain",
                            pid = raw.pid,
                            comm = %nn_model::log_escape::Escaped(comm),
                            src = %src,
                            dst = %dst,
                            corr_start_ns = corr_start_ns(&raw.flow_id),
                            close_reason = raw.close_reason,
                            bytes_sent = raw.bytes_sent,
                            bytes_recv = raw.bytes_recv,
                            "net drain: TCP close had a kernel flow id but no pending flow — row NOT recorded"
                        );
                    }
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
                comm,
                // External audit NETR-008: the sender's image, read before
                // the tracker's lock (a datagram record is emitted while
                // its sender runs).
                exe: lineage.image_path(raw.pid),
                // External audit NET-016: who holds the PID, for the DNS
                // attribution below.
                proc_start_ns: lineage.start_floor_ns(raw.pid).unwrap_or(0),
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
    // never observed within the TTL). External audit NET-016: only the
    // queries made since the connecting process started.
    if let Some(qname) =
        dns_cache.lookup_for_connect(event.pid, event.start_ns, event.proc_start_ns)
    {
        event.resolved_hostname = Some(qname);
    }

    // External audit NET-017 (lab PR 207): the rows whose names and
    // handshakes no rule can read (DNS over TLS, QUIC), for `net status`.
    crate::net::blind_spots::note_flow(&event);

    // External audit NET-019 (design §6.5): past its uid's budget a row
    // is held back from the rules — never one a killing rule could match
    // or one of a process with a chain precursor (`net::limiter`).
    let skipped = gate.hold_back(&event, Instant::now());

    // Persist BEFORE emitting to the bus — design §6.5 evidence-
    // preservation contract (the on-disk row is the IR-grade
    // record; the rule engine emission is the live-defense path).
    // Append failures are warn-logged + we still emit on the bus
    // so the deterministic rule never silently misses a flow.
    // Lab PR 218: without the log (it could not be opened at boot, a
    // signed `subsystem_degraded` says so) the row goes to the rules only.
    if let Some(db) = netflow_db {
        if let Err(e) = db.lock().append(&event, skipped) {
            warn!(error = %e, "appending NetFlowEntry to netflow log failed");
        }
    }
    if skipped {
        return;
    }

    if event_tx.send(Event::NetFlow(event)).await.is_err() {
        // Event bus closed — main loop is shutting down. The
        // outer drain_loop will see the next readable_mut() error
        // and exit naturally; nothing to do here.
    }
}

async fn process_listen_record(
    bytes: &[u8],
    listener_db: Option<&Arc<Mutex<NetListenerDb>>>,
    event_tx: &crate::sensors::bus::BusSender,
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
    // External audit EBPF-013: listen() calls the kernel's record budgets
    // held back since this process's previous record.
    let floods = nn_model::sensor_floods(
        nn_model::FloodSource::Listen,
        raw.pid,
        raw.uid,
        &ev.comm,
        raw.held,
        raw.held_uid,
        raw.timestamp_ns,
    );
    if let Some(db) = listener_db {
        if let Err(e) = db.lock().append(&ev) {
            warn!(error = %e, "appending NetListenerEntry to listeners log failed");
        }
    }
    if event_tx.send(Event::NetListener(ev)).await.is_err() {
        // bus closed
        return;
    }
    for flood in floods.into_iter().flatten() {
        if event_tx.send(flood).await.is_err() {
            return;
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────

/// The canonical address (external audit NET-001: an IPv4-mapped IPv6
/// address is the IPv4 address it maps).
fn decode_addr(family: u8, bytes: [u8; 16]) -> IpAddr {
    nn_model::netaddr::canonical_ip(family, &bytes)
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).into_owned()
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

/// Legacy v1 netflow hash — production now uses the chainlog core;
/// retained ONLY for the BUG-026 byte-compat gate.
#[cfg(test)]
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

/// External audit EVD-023 (NN-AUD-427, lab PR 204): an entry that still
/// carries `entry_hash` or `agent_sig` is an error in every build.
fn compute_listener_entry_hash(entry: &NetListenerEntry) -> Result<[u8; 32]> {
    crate::chain_anchor::check_unsealed(&entry.entry_hash, &entry.agent_sig)?;
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
    use nn_model::telemetry::TlsFingerprint;
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
            proc_start_ns: 0,
            bytes_sent: 100,
            bytes_recv: 200,
            resolved_hostname: Some("example.com".to_string()),
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
            phase: Default::default(),
            observed_ns: 0,
        }
    }

    /// Lab PR 224 (CM-02 b): the snapshots handed to the rules name the
    /// image the process runs now (it executed another since its connect),
    /// and a flow whose process is gone, or whose pid a later process
    /// holds, is not handed out.
    #[test]
    fn snapshot_rows_name_the_current_image_and_skip_the_gone() {
        use crate::net::flow_tracker::TcpConnectInfo;
        let tmp = tempfile::tempdir().unwrap();
        let ticks: u64 = 1_000; // a start long before the connects below
        for pid in [4700u32, 4702] {
            let dir = tmp.path().join(pid.to_string());
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(
                dir.join("stat"),
                format!("{pid} (p) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
            )
            .unwrap();
        }
        // pid 4702 is held by a process started after its connect.
        std::fs::write(
            tmp.path().join("4702/stat"),
            "4702 (p) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999999999999 0 0\n",
        )
        .unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::new(tmp.path());
        lineage.ingest_spawn(4700, 1, "/var/tmp/nn-ms/stage2", 1);
        let tracker = Mutex::new(FlowTracker::default());
        let start = 100_000_000_000u64;
        for (pid, sk) in [(4700u32, 1u64), (4701, 2), (4702, 3)] {
            tracker.lock().on_tcp_connect(&TcpConnectInfo {
                start_ns: start,
                sk_ptr: sk,
                family: 2,
                src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                src_port: 0,
                dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                dst_port: 8443,
                proto: 6,
                pid,
                uid: 0,
                comm: "python3".into(),
                exe: Some("/usr/bin/python3.12".into()),
                proc_start_ns: 0,
            });
        }
        let rows = due_snapshot_rows(
            &tracker,
            &DnsCache::default(),
            &lineage,
            &SnapshotPolicy::default(),
            start + 61_000_000_000,
        );
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].pid, 4700);
        assert_eq!(rows[0].exe.as_deref(), Some("/var/tmp/nn-ms/stage2"));
        assert_eq!(rows[0].phase, nn_model::telemetry::FlowPhase::Snapshot);
    }

    fn fresh_key() -> AgentSigningKey {
        let dir = tempfile::tempdir().unwrap();
        AgentSigningKey::load_or_bootstrap(&dir.path().join("k.sig")).unwrap()
    }

    /// External audit NET-003: a torn last write of the listener log no
    /// longer fails every later open (the network drain never started).
    #[test]
    fn a_torn_listener_log_reopens_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow_listeners.jsonl");
        let ev = NetListenerEvent {
            timestamp_ns: 1,
            family: 2,
            bind_addr: "0.0.0.0".parse().unwrap(),
            bind_port: 8080,
            proto: 6,
            pid: 42,
            uid: 0,
            comm: "nc".to_string(),
            exe: None,
        };
        let first = {
            let mut db = NetListenerDb::open(&path, fresh_key(), [0u8; 16]).unwrap();
            db.append(&ev).unwrap()
        };
        let mut body = std::fs::read(&path).unwrap();
        body.extend_from_slice(br#"{"ts":"2026-10-13T00:00:00Z","timestamp_ns":2,"fam"#);
        std::fs::write(&path, &body).unwrap();
        let mut db = NetListenerDb::open(&path, fresh_key(), [0u8; 16]).expect("reopens");
        assert!(db.take_tail_repair().is_some());
        assert_eq!(db.last_hash(), first.entry_hash);
        db.append(&ev).expect("appends continue");
    }

    /// BUG-026 migration GATE for netflow: an existing on-disk **v1**
    /// `netflow.jsonl` line MUST still verify under the rotation-aware
    /// reader after the payload/envelope split — the same two-way proof
    /// as the fim_drift gate (byte-equality + end-to-end of a really-
    /// signed legacy line).
    #[test]
    fn bug026_legacy_v1_netflow_line_still_verifies() {
        use crate::chainlog::{verify_log_set, ChainLine};
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let pk = key.verifying_key();

        // A real legacy v1 line — body fields, then the OLD hash + sign.
        let mut legacy = NetFlowEntry {
            ts: "2026-05-30T00:00:00.000000Z".to_string(),
            flow_id: "abc".to_string(),
            start_ns: 1000,
            end_ns: 2000,
            family: 2,
            src_addr: "192.0.2.10".to_string(),
            src_port: 54321,
            dst_addr: "1.2.3.4".to_string(),
            dst_port: 443,
            proto: 6,
            pid: 1234,
            uid: 1000,
            comm: "curl".to_string(),
            exe: Some("/usr/bin/curl".to_string()),
            bytes_sent: 100,
            bytes_recv: 200,
            resolved_hostname: Some("example.com".to_string()),
            ja3: None,
            ja4: None,
            sni: None,
            close_reason: 0,
            agent_id: "07".repeat(16),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let h = compute_flow_entry_hash(&legacy).unwrap();
        legacy.entry_hash = hex::encode(h);
        legacy.agent_sig = B64.encode(key.sign(&h).to_bytes());

        // (1) byte-equality.
        let envelope = ChainLine {
            payload: NetFlowPayload {
                ts: legacy.ts.clone(),
                flow_id: legacy.flow_id.clone(),
                start_ns: legacy.start_ns,
                end_ns: legacy.end_ns,
                family: legacy.family,
                src_addr: legacy.src_addr.clone(),
                src_port: legacy.src_port,
                dst_addr: legacy.dst_addr.clone(),
                dst_port: legacy.dst_port,
                proto: legacy.proto,
                pid: legacy.pid,
                uid: legacy.uid,
                comm: legacy.comm.clone(),
                exe: legacy.exe.clone(),
                bytes_sent: legacy.bytes_sent,
                bytes_recv: legacy.bytes_recv,
                resolved_hostname: legacy.resolved_hostname.clone(),
                ja3: legacy.ja3.clone(),
                ja4: legacy.ja4.clone(),
                sni: legacy.sni.clone(),
                close_reason: legacy.close_reason,
                agent_id: legacy.agent_id.clone(),
                decision_engine_skipped: false,
            },
            fmt_ver: None,
            prev_hash: legacy.prev_hash.clone(),
            entry_hash: legacy.entry_hash.clone(),
            agent_sig: legacy.agent_sig.clone(),
        };
        assert_eq!(
            serde_json::to_string(&envelope).unwrap(),
            serde_json::to_string(&legacy).unwrap(),
            "ChainLine<NetFlowPayload>{{fmt_ver:None}} must serialise byte-identically \
             to the legacy NetFlowEntry — else on-disk v1 lines stop verifying"
        );

        // (2) end-to-end.
        let log = dir.path().join("netflow.jsonl");
        std::fs::write(
            &log,
            format!("{}\n", serde_json::to_string(&legacy).unwrap()),
        )
        .unwrap();
        let report = verify_log_set::<NetFlowPayload>(&log, &pk).unwrap();
        assert_eq!(report.total_records, 1);
    }

    /// N9 drain test #1 — appending a NetFlowEvent yields a row
    /// with the chain primitives populated + readable back from
    /// the file. Pins the §4.4 on-disk schema is what the chain
    /// produces.
    #[test]
    fn netflow_db_append_writes_one_chained_row() {
        use crate::chainlog::{
            verify_log_set, ChainLine, NoProtection, RotationConfig, CHAINLOG_FMT_V3,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key = fresh_key();
        let pk = key.verifying_key();
        let mut db = NetFlowDb::open(
            &path,
            key,
            [0u8; 16],
            std::sync::Arc::new(NoProtection),
            RotationConfig::default(),
        )
        .unwrap();
        let ev = test_event();
        let entry_hash = db.append(&ev, false).unwrap();

        // Read the PERSISTED row and assert the SAME body properties the
        // pre-migration test checked — now on the ChainLine payload — plus
        // that the chain VERIFIES (not merely that append returned a hash).
        let body = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(rows.len(), 1, "expected one chained row");
        let line: ChainLine<NetFlowPayload> = serde_json::from_str(rows[0]).unwrap();
        assert_eq!(line.payload.flow_id, "abc");
        assert_eq!(line.payload.dst_addr, "1.2.3.4");
        assert_eq!(line.payload.dst_port, 443);
        assert_eq!(
            line.payload.resolved_hostname,
            Some("example.com".to_string())
        );
        assert_eq!(line.entry_hash, entry_hash);
        assert_eq!(line.prev_hash.len(), 64);
        assert_eq!(line.entry_hash.len(), 64);
        assert!(!line.agent_sig.is_empty());
        assert_eq!(
            line.fmt_ver,
            Some(CHAINLOG_FMT_V3),
            "new lines are v3 (lab PR 204)"
        );

        let report = verify_log_set::<NetFlowPayload>(&path, &pk).unwrap();
        assert_eq!(report.total_records, 1);
    }

    /// N9 drain test #2 — chain continuity across two appends:
    /// row 2's `prev_hash` MUST equal row 1's `entry_hash`.
    /// Same shape as the audit + drift chain tests.
    #[test]
    fn netflow_db_chains_prev_hash_into_next_entry_hash() {
        use crate::chainlog::{verify_log_set, ChainLine, NoProtection, RotationConfig};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key = fresh_key();
        let pk = key.verifying_key();
        let mut db = NetFlowDb::open(
            &path,
            key,
            [1u8; 16],
            std::sync::Arc::new(NoProtection),
            RotationConfig::default(),
        )
        .unwrap();
        let h1 = db.append(&test_event(), false).unwrap();
        let mut ev2 = test_event();
        ev2.flow_id = "def".to_string();
        let h2 = db.append(&ev2, false).unwrap();
        assert_ne!(h1, h2, "two distinct rows have distinct entry hashes");
        assert_eq!(db.last_hash(), h2);

        // The on-disk row 2's prev_hash MUST equal row 1's entry_hash —
        // the chain-continuity property the pre-migration test pinned.
        let body = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<ChainLine<NetFlowPayload>> = body
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].entry_hash, h1);
        assert_eq!(
            rows[1].prev_hash, h1,
            "row2.prev_hash must chain off row1.entry_hash"
        );
        assert_eq!(rows[1].entry_hash, h2);
        verify_log_set::<NetFlowPayload>(&path, &pk).unwrap();
    }

    /// N9 drain test #3 — reopening a db on an existing log picks
    /// up the tail hash, so the next append chains off the prior
    /// run's last row. Closes the boot-replay invariant.
    /// `AgentSigningKey` is intentionally non-Clone — we mint
    /// twice from the same key file via `load_or_bootstrap` so
    /// the second db sees the same signing identity as the first.
    #[test]
    fn netflow_db_reopen_resumes_chain_from_tail() {
        use crate::chainlog::{verify_log_set, ChainLine, NoProtection, RotationConfig};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key_path = dir.path().join("k.sig");
        let pk = AgentSigningKey::load_or_bootstrap(&key_path)
            .unwrap()
            .verifying_key();

        let key1 = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut db = NetFlowDb::open(
            &path,
            key1,
            [2u8; 16],
            std::sync::Arc::new(NoProtection),
            RotationConfig::default(),
        )
        .unwrap();
        let h1 = db.append(&test_event(), false).unwrap();
        drop(db);

        let key2 = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut db = NetFlowDb::open(
            &path,
            key2,
            [2u8; 16],
            std::sync::Arc::new(NoProtection),
            RotationConfig::default(),
        )
        .unwrap();
        assert_eq!(db.last_hash(), h1, "reopen must resume from the prior tail");
        let mut ev2 = test_event();
        ev2.flow_id = "next".to_string();
        let h2 = db.append(&ev2, false).unwrap();

        // The post-reopen append must chain off the prior run's last row,
        // and the whole (across-reopen) chain must verify.
        let body = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<ChainLine<NetFlowPayload>> = body
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].prev_hash, h1);
        assert_eq!(rows[1].entry_hash, h2);
        verify_log_set::<NetFlowPayload>(&path, &pk).unwrap();
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
        let mut db = NetFlowDb::open(
            &path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let mut ev = test_event();
        ev.tls_fingerprint = Some(TlsFingerprint {
            ja3: "deadbeef".to_string(),
            ja4: "t13d1517h2".to_string(),
            ja3_raw: "0-1-2".to_string(),
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
        });
        db.append(&ev, false).unwrap();

        // Assert the persisted ROW preserves every fingerprint field.
        let body = std::fs::read_to_string(&path).unwrap();
        let line: crate::chainlog::ChainLine<NetFlowPayload> =
            serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(line.payload.ja3, Some("deadbeef".to_string()));
        assert_eq!(line.payload.ja4, Some("t13d1517h2".to_string()));
        assert_eq!(line.payload.sni, Some("example.com".to_string()));
    }

    /// A netflow log signed with the key at `<dir>/k.sig`.
    fn open_db(path: &Path) -> NetFlowDb {
        NetFlowDb::open(
            path,
            AgentSigningKey::load_or_bootstrap(&path.with_file_name("k.sig")).unwrap(),
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap()
    }

    /// External audit NET-019: the rows are fsynced together, at most
    /// every 100 ms, not one fsync per row; the chain verifies.
    #[test]
    fn group_commit_fsyncs_at_most_every_100ms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let mut db = open_db(&path);
        let t0 = Instant::now();
        // 500 rows: clear of the active checkpoint every 1000 records
        // (NN-AUD-109), which makes its rows durable first, an fsync of
        // its own.
        for i in 0..500 {
            let mut ev = test_event();
            ev.flow_id = format!("f{i}");
            db.append(&ev, false).unwrap();
            assert!(!db.sync_if_due(t0 + Duration::from_millis(1)).unwrap());
        }
        assert_eq!(db.fsyncs(), 0, "no fsync per row");
        assert!(db.sync_if_due(t0 + NETFLOW_SYNC_INTERVAL).unwrap());
        assert_eq!(db.fsyncs(), 1);
        // Nothing written since: no fsync, whatever the time.
        assert!(!db.sync_if_due(t0 + Duration::from_secs(5)).unwrap());
        db.append(&test_event(), false).unwrap();
        assert!(!db.sync_if_due(t0 + Duration::from_millis(150)).unwrap());
        assert!(db.sync_if_due(t0 + Duration::from_millis(200)).unwrap());
        assert_eq!(db.fsyncs(), 2);
        let report =
            crate::chainlog::verify_log_set::<NetFlowPayload>(&path, &fresh_key_pk(dir.path()))
                .unwrap_or_else(|_| panic!("verifies"));
        assert_eq!(report.total_records, 501);
    }

    /// The listener log uses the same group commit.
    #[test]
    fn listener_rows_are_committed_together() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow_listeners.jsonl");
        let mut db = NetListenerDb::open(&path, fresh_key(), [0u8; 16]).unwrap();
        let ev = NetListenerEvent {
            timestamp_ns: 1,
            family: 2,
            bind_addr: "0.0.0.0".parse().unwrap(),
            bind_port: 8080,
            proto: 6,
            pid: 42,
            uid: 0,
            comm: "nc".to_string(),
            exe: None,
        };
        let t0 = Instant::now();
        for _ in 0..10 {
            db.append(&ev).unwrap();
            assert!(!db.sync_if_due(t0).unwrap());
        }
        assert!(db.sync_if_due(t0 + NETFLOW_SYNC_INTERVAL).unwrap());
        assert!(!db.sync_if_due(t0 + Duration::from_secs(1)).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 10);
    }

    /// The verifying key of the logs `open_db` opens in `dir`.
    fn fresh_key_pk(dir: &Path) -> ed25519_dalek::VerifyingKey {
        AgentSigningKey::load_or_bootstrap(&dir.join("k.sig"))
            .unwrap()
            .verifying_key()
    }

    fn close_raw(uid: u32, pid: u32, dst: [u8; 4], dport: u16, corr: u8) -> Vec<u8> {
        let mut raw = NetFlowCloseRaw::zeroed();
        raw.timestamp_ns = 5_000_000_000 + u64::from(corr);
        raw.flow_id = [corr; 16];
        raw.pid = pid;
        raw.uid = uid;
        raw.src_addr[..4].copy_from_slice(&[100, 64, 0, 2]);
        raw.dst_addr[..4].copy_from_slice(&dst);
        raw.comm[..7].copy_from_slice(b"nnflood");
        raw.family = 2;
        raw.proto = IPPROTO_TCP;
        raw.src_port = 40_000;
        raw.dst_port = dport;
        bytemuck::bytes_of(&raw).to_vec()
    }

    /// A refused loopback connect's close (lab PR 246, the KVM failure of
    /// 27/10/2026): the kernel cleared the destination port, its
    /// correlator names the connect at `connect_ns`.
    fn refused_close(connect_ns: u64, sk_ptr: u64) -> NetFlowCloseRaw {
        let mut raw = NetFlowCloseRaw::zeroed();
        raw.timestamp_ns = connect_ns + 40_000;
        raw.flow_id = FlowTracker::corr_id(connect_ns, sk_ptr);
        raw.pid = 9825;
        raw.src_addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        raw.dst_addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        raw.comm[..4].copy_from_slice(b"bash");
        raw.family = 2;
        raw.proto = IPPROTO_TCP;
        raw.src_port = 40_000;
        raw
    }

    fn refused_connect(connect_ns: u64, sk_ptr: u64) -> crate::net::flow_tracker::TcpConnectInfo {
        crate::net::flow_tracker::TcpConnectInfo {
            start_ns: connect_ns,
            sk_ptr,
            family: 2,
            src_addr: "0.0.0.0".parse().unwrap(),
            src_port: 0,
            dst_addr: "127.0.0.1".parse().unwrap(),
            dst_port: 41147,
            proto: 6,
            pid: 9825,
            uid: 0,
            comm: "bash".into(),
            exe: Some("/usr/bin/bash".into()),
            proc_start_ns: 0,
        }
    }

    /// Lab PR 246: a TCP close is held until the connect pump has put its
    /// connect on the bus (announced), at most `CONNECT_WAIT` from the
    /// connect's time; then it resolves against its connect — the
    /// connect's destination, not the port 0 the kernel left on a refused
    /// connect. No wait for a close whose connect is old, is announced,
    /// is a kernel lookup miss, for a UDP record, or with no connect pump.
    #[tokio::test]
    async fn a_close_is_held_until_its_connect_is_on_the_bus() {
        use std::time::Instant as StdInstant;
        let zero = Duration::ZERO;
        let tracker = Arc::new(Mutex::new(FlowTracker::default()));
        tracker.lock().set_connect_pump(true);

        // The connect not read yet: the close waits...
        let t0 = monotonic_ns();
        let close = refused_close(t0, 0x5eed);
        assert!(
            tokio::time::timeout(zero, connect_barrier(&[close], &tracker))
                .await
                .is_err(),
            "a fresh close waits for its connect"
        );
        // ...and goes on once the connect pump announces it.
        let waiting = {
            let tracker = Arc::clone(&tracker);
            tokio::spawn(async move {
                let began = StdInstant::now();
                connect_barrier(&[close], &tracker).await;
                began.elapsed()
            })
        };
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        {
            let mut t = tracker.lock();
            assert!(t.on_tcp_connect(&refused_connect(t0, 0x5eed)).is_some());
            t.announce(&close.flow_id);
        }
        let waited = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("woken")
            .unwrap();
        assert!(
            waited < CONNECT_WAIT,
            "woken by the announcement: {waited:?}"
        );
        let info = TcpCloseInfo {
            end_ns: close.timestamp_ns,
            corr_id: close.flow_id,
            src_addr: "127.0.0.1".parse().unwrap(),
            src_port: 40_000,
            bytes_sent: 0,
            bytes_recv: 0,
            close_reason: 0,
            family: 2,
            dst_addr: "127.0.0.1".parse().unwrap(),
            dst_port: 0,
            pid: 9825,
            uid: 0,
            comm: "bash".into(),
        };
        let row = tracker.lock().on_tcp_close(&info).expect("resolved");
        assert_eq!((row.start_ns, row.dst_port), (t0, 41147));
        assert_eq!(row.exe.as_deref(), Some("/usr/bin/bash"));

        // No wait: an announced connect, an old connect, a kernel lookup
        // miss, a UDP record.
        let announced = refused_close(monotonic_ns(), 0x6eed);
        {
            let mut t = tracker.lock();
            let c = refused_connect(FlowTracker::corr_start_ns(&announced.flow_id), 0x6eed);
            t.on_tcp_connect(&c);
            t.announce(&announced.flow_id);
        }
        let old = refused_close(
            monotonic_ns().saturating_sub(2 * CONNECT_WAIT.as_nanos() as u64),
            0x7eed,
        );
        let mut miss = refused_close(monotonic_ns(), 0x8eed);
        miss.flow_id = [0u8; 16];
        let mut udp = refused_close(monotonic_ns(), 0x9eed);
        udp.proto = IPPROTO_UDP;
        for raw in [announced, old, miss, udp] {
            assert!(
                tokio::time::timeout(zero, connect_barrier(&[raw], &tracker))
                    .await
                    .is_ok(),
                "no wait: {raw:?}"
            );
        }

        // A connect never announced: the close goes on at the bound.
        let late = refused_close(
            monotonic_ns()
                .saturating_sub((CONNECT_WAIT - Duration::from_millis(60)).as_nanos() as u64),
            0xaeed,
        );
        let began = StdInstant::now();
        tokio::time::timeout(Duration::from_secs(5), connect_barrier(&[late], &tracker))
            .await
            .expect("bounded");
        assert!(began.elapsed() >= Duration::from_millis(20));

        // No connect pump: nothing waits.
        tracker.lock().set_connect_pump(false);
        let fresh = refused_close(monotonic_ns(), 0xbeed);
        assert!(
            tokio::time::timeout(zero, connect_barrier(&[fresh], &tracker))
                .await
                .is_ok()
        );
    }

    /// External audit NET-019 + NET-012 through the drain's record path:
    /// past the uid's budget a row is written with
    /// `decision_engine_skipped` and not sent to the rules; a blocklisted
    /// destination from the same uid still is; a row the close
    /// synthesised names its image.
    #[tokio::test]
    async fn suppressed_flow_is_still_persisted_and_marked() {
        use crate::decision::correlation::CorrelationStore;
        use crate::net::limiter::UidPacer;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key_path = dir.path().join("k.sig");
        let db = Arc::new(Mutex::new(
            NetFlowDb::open(
                &path,
                AgentSigningKey::load_or_bootstrap(&key_path).unwrap(),
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap(),
        ));
        let tracker = Arc::new(Mutex::new(FlowTracker::default()));
        let dns = Arc::new(DnsCache::default());
        let proc_root = tempfile::tempdir().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::new(proc_root.path());
        lineage.ingest_spawn_with_argv(4242, 1, "/opt/nnx/nnflood", &["nnflood".to_string()], 1);
        let bl = crate::net::blocklist::NetBlocklist::from_entries([
            crate::net::blocklist::NetBlocklistEntry::Cidr {
                net: "192.0.2.0".parse().unwrap(),
                prefix: 24,
            },
        ]);
        let mut gate = RuleGate::with_pacer(
            Arc::new(bl),
            Arc::new(Mutex::new(CorrelationStore::new())),
            UidPacer::with_rate(2, 1),
        );
        let (tx, mut rx) = crate::sensors::bus::channel();
        for corr in 1..=5u8 {
            let raw = close_raw(1000, 4242, [100, 64, 0, 1], 8080, corr);
            process_close_record(&raw, &tracker, &dns, Some(&db), &lineage, &mut gate, &tx).await;
        }
        let raw = close_raw(1000, 4242, [192, 0, 2, 10], 8080, 6);
        process_close_record(&raw, &tracker, &dns, Some(&db), &lineage, &mut gate, &tx).await;
        drop(tx);
        let mut sent = Vec::new();
        while let Some(Event::NetFlow(nf)) = rx.recv().await.map(|r| r.event) {
            sent.push(nf.dst_addr.to_string());
        }
        assert_eq!(
            sent,
            ["100.64.0.1", "100.64.0.1", "192.0.2.10"],
            "the burst, then only the blocklisted row"
        );
        let rows: Vec<crate::chainlog::ChainLine<NetFlowPayload>> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 6, "every row is written");
        let skipped: Vec<bool> = rows
            .iter()
            .map(|r| r.payload.decision_engine_skipped)
            .collect();
        assert_eq!(skipped, [false, false, true, true, true, false]);
        assert!(rows
            .iter()
            .all(|r| r.payload.exe.as_deref() == Some("/opt/nnx/nnflood")));
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.matches("\"decision_engine_skipped\":true").count(), 3);
        assert_eq!(body.matches("decision_engine_skipped").count(), 3);
        let pk = AgentSigningKey::load_or_bootstrap(&key_path)
            .unwrap()
            .verifying_key();
        crate::chainlog::verify_log_set::<NetFlowPayload>(&path, &pk).unwrap();
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// External audit EBPF-019: a TCP close with a kernel correlator and
    /// no pending flow is a WARN; its fields carry the connect's timestamp
    /// (the correlator's first half), never the socket's kernel address
    /// (the second half), which the journal's readers must not learn.
    #[tokio::test]
    async fn close_without_pending_flow_logs_no_kernel_pointer() {
        use crate::decision::correlation::CorrelationStore;
        use crate::net::limiter::UidPacer;
        const SK_PTR: u64 = 0xffff_8881_2345_6780;
        const START_NS: u64 = 5_123_456_789;
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Mutex::new(
            NetFlowDb::open(
                &dir.path().join("netflow.jsonl"),
                AgentSigningKey::load_or_bootstrap(&dir.path().join("k.sig")).unwrap(),
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap(),
        ));
        let tracker = Arc::new(Mutex::new(FlowTracker::default()));
        let dns = Arc::new(DnsCache::default());
        let proc_root = tempfile::tempdir().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::new(proc_root.path());
        let mut gate = RuleGate::with_pacer(
            Arc::new(crate::net::blocklist::NetBlocklist::from_entries([])),
            Arc::new(Mutex::new(CorrelationStore::new())),
            UidPacer::with_rate(100, 100),
        );
        let (tx, _rx) = crate::sensors::bus::channel();
        // No destination either: the tracker cannot synthesise a row
        // (NET-012), the path that logs the WARN.
        let mut raw: NetFlowCloseRaw =
            bytemuck::pod_read_unaligned(&close_raw(1000, 4242, [0, 0, 0, 0], 0, 1));
        raw.flow_id = FlowTracker::corr_id(START_NS, SK_PTR);
        let bytes = bytemuck::bytes_of(&raw).to_vec();

        let out = Captured::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(out.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        {
            let _guard = tracing::subscriber::set_default(sub);
            process_close_record(&bytes, &tracker, &dns, Some(&db), &lineage, &mut gate, &tx).await;
        }
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let warn: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("WARN") && l.contains("no pending flow"))
            .collect();
        assert_eq!(warn.len(), 1, "{text}");
        let line = warn[0];
        assert!(
            line.contains(&format!("corr_start_ns={START_NS}")),
            "{line}"
        );
        // No field value is a kernel address (0xffff_8000_0000_0000 and
        // up), in decimal or as 16 hex digits, nor the correlator's second
        // half in its byte order.
        for token in line.split(|c: char| !c.is_ascii_hexdigit()) {
            if let Ok(v) = token.parse::<u64>() {
                assert!(v < 0xffff_8000_0000_0000, "decimal {token} in {line}");
            }
            for w in 0..token.len().saturating_sub(15) {
                if let Ok(v) = u64::from_str_radix(&token[w..w + 16], 16) {
                    assert!(v < 0xffff_8000_0000_0000, "hex {token} in {line}");
                }
            }
        }
        assert!(!line.contains(&hex::encode(raw.flow_id)), "{line}");
        assert!(!line.contains(&hex::encode(SK_PTR.to_le_bytes())), "{line}");
        assert!(!line.contains(&format!("{SK_PTR:x}")), "{line}");
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
        let db = NetFlowDb::open(
            &path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
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

    /// A record path's state for the tests below: a netflow log in a
    /// temporary directory, an empty tracker, DNS cache and lineage, a gate
    /// that holds nothing back.
    struct Harness {
        dir: tempfile::TempDir,
        _proc: tempfile::TempDir,
        db: Option<Arc<Mutex<NetFlowDb>>>,
        tracker: Arc<Mutex<FlowTracker>>,
        dns: Arc<DnsCache>,
        lineage: crate::posture::lineage::AuthSessionTracker,
        gate: RuleGate,
    }

    fn harness() -> Harness {
        use crate::decision::correlation::CorrelationStore;
        use crate::net::limiter::UidPacer;
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Mutex::new(
            NetFlowDb::open(
                &dir.path().join("netflow.jsonl"),
                AgentSigningKey::load_or_bootstrap(&dir.path().join("k.sig")).unwrap(),
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap(),
        ));
        let proc_root = tempfile::tempdir().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::new(proc_root.path());
        Harness {
            dir,
            _proc: proc_root,
            db: Some(db),
            tracker: Arc::new(Mutex::new(FlowTracker::default())),
            dns: Arc::new(DnsCache::default()),
            lineage,
            gate: RuleGate::with_pacer(
                Arc::new(crate::net::blocklist::NetBlocklist::from_entries([])),
                Arc::new(Mutex::new(CorrelationStore::new())),
                UidPacer::with_rate(100, 100),
            ),
        }
    }

    impl Harness {
        async fn close(&mut self, raw: &NetFlowCloseRaw, tx: &crate::sensors::bus::BusSender) {
            process_close_record(
                bytemuck::bytes_of(raw),
                &self.tracker,
                &self.dns,
                self.db.as_ref(),
                &self.lineage,
                &mut self.gate,
                tx,
            )
            .await;
        }
    }

    /// `comm` as the kernel can hand it: a name, its NUL, then a byte left
    /// over from a longer earlier name (`prctl(PR_SET_NAME)` writes the
    /// new name and its NUL only).
    const COMM_WITH_TAIL: [u8; 16] = *b"curl\0Xvil\0\0\0\0\0\0\0";

    /// External audit NET-020 (3) (lab PR 207): the TCP close (a row it
    /// synthesises, and the WARN of one it cannot record), the UDP send and
    /// the listener give one name for the same comm bytes — the TCP branch
    /// kept `"curl\0Xvil"` (lossy, then only the trailing NULs trimmed), the
    /// others `"curl"`, and the comm allowlist saw either.
    #[tokio::test]
    async fn comm_decoding_is_identical_across_drain_branches() {
        let mut h = harness();
        let (tx, mut rx) = crate::sensors::bus::channel();

        // TCP: a close whose connect was not seen — the tracker
        // synthesises the row from the close's own fields (NET-012).
        let mut tcp: NetFlowCloseRaw =
            bytemuck::pod_read_unaligned(&close_raw(1000, 4242, [100, 64, 0, 1], 8080, 7));
        tcp.comm = COMM_WITH_TAIL;
        h.close(&tcp, &tx).await;

        // UDP.
        let mut udp = tcp;
        udp.proto = IPPROTO_UDP;
        udp.flow_id = [0u8; 16];
        udp.dst_port = 5353;
        h.close(&udp, &tx).await;

        // Listener.
        let mut listen = NetListenRaw::zeroed();
        listen.timestamp_ns = 6_000_000_000;
        listen.pid = 4242;
        listen.uid = 1000;
        listen.family = 2;
        listen.proto = IPPROTO_TCP;
        listen.bind_port = 9000;
        listen.comm = COMM_WITH_TAIL;
        process_listen_record(bytemuck::bytes_of(&listen), None, &tx).await;

        // TCP close the tracker cannot record (no destination): the WARN.
        let mut orphan = tcp;
        orphan.dst_addr = [0u8; 16];
        orphan.dst_port = 0;
        orphan.flow_id = [9u8; 16];
        let out = Captured::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(out.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        {
            let _guard = tracing::subscriber::set_default(sub);
            h.close(&orphan, &tx).await;
        }
        drop(tx);

        let mut names = Vec::new();
        while let Some(ev) = rx.recv().await.map(|r| r.event) {
            match ev {
                Event::NetFlow(nf) => names.push(("flow", nf.proto, nf.comm)),
                Event::NetListener(l) => names.push(("listener", l.proto, l.comm)),
                _ => {}
            }
        }
        assert_eq!(
            names,
            [
                ("flow", IPPROTO_TCP, "curl".to_string()),
                ("flow", IPPROTO_UDP, "curl".to_string()),
                ("listener", IPPROTO_TCP, "curl".to_string()),
            ]
        );
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let warn: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("WARN") && l.contains("no pending flow"))
            .collect();
        assert_eq!(warn.len(), 1, "{text}");
        assert!(warn[0].contains("comm=curl "), "{}", warn[0]);
        // The on-disk rows say the same.
        let rows: Vec<crate::chainlog::ChainLine<NetFlowPayload>> =
            std::fs::read_to_string(h.dir.path().join("netflow.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.payload.comm == "curl"), "{rows:?}");
    }

    /// External audit NET-017 (lab PR 207): the drain counts the rows to
    /// TCP/853 (DNS over TLS) and UDP/443 (QUIC) it records, a held-back
    /// one too, for `nn-admin net status`; TCP/443 is not counted.
    #[tokio::test]
    async fn drain_counts_dot_and_quic_rows() {
        let mut h = harness();
        let (tx, _rx) = crate::sensors::bus::channel();
        let before = crate::net::blind_spots::encrypted_flows();
        let dot: NetFlowCloseRaw =
            bytemuck::pod_read_unaligned(&close_raw(1000, 4243, [1, 1, 1, 1], 853, 11));
        h.close(&dot, &tx).await;
        let mut quic = dot;
        quic.proto = IPPROTO_UDP;
        quic.flow_id = [0u8; 16];
        quic.dst_port = 443;
        h.close(&quic, &tx).await;
        let after = crate::net::blind_spots::encrypted_flows();
        // Other tests run at the same time: at least these.
        assert!(after.dot > before.dot, "{before:?} {after:?}");
        assert!(after.quic > before.quic, "{before:?} {after:?}");
        let rows = std::fs::read_to_string(h.dir.path().join("netflow.jsonl")).unwrap();
        assert_eq!(rows.lines().count(), 2, "both rows recorded");
    }

    /// Lab PR 218 (external review P0 C-14): without the netflow log the
    /// drain still hands every flow and listener to the rules — the TCP
    /// close, the UDP send, the listener — and writes nothing.
    #[tokio::test]
    async fn flows_reach_the_rules_without_the_netflow_log() {
        let mut h = harness();
        h.db = None;
        let (tx, mut rx) = crate::sensors::bus::channel();
        let tcp: NetFlowCloseRaw =
            bytemuck::pod_read_unaligned(&close_raw(1000, 4244, [100, 64, 0, 2], 8443, 12));
        h.close(&tcp, &tx).await;
        let mut udp = tcp;
        udp.proto = IPPROTO_UDP;
        udp.flow_id = [0u8; 16];
        udp.dst_port = 5353;
        h.close(&udp, &tx).await;
        let mut listen = NetListenRaw::zeroed();
        listen.timestamp_ns = 7_000_000_000;
        listen.pid = 4244;
        listen.family = 2;
        listen.proto = IPPROTO_TCP;
        listen.bind_port = 9001;
        process_listen_record(bytemuck::bytes_of(&listen), None, &tx).await;
        group_commit(None, None);
        drop(tx);
        let mut seen = Vec::new();
        while let Some(ev) = rx.recv().await.map(|r| r.event) {
            match ev {
                Event::NetFlow(nf) => seen.push(("flow", nf.proto, nf.dst_port)),
                Event::NetListener(l) => seen.push(("listener", l.proto, l.bind_port)),
                _ => {}
            }
        }
        assert_eq!(
            seen,
            [
                ("flow", IPPROTO_TCP, 8443),
                ("flow", IPPROTO_UDP, 5353),
                ("listener", IPPROTO_TCP, 9001),
            ]
        );
        let rows = std::fs::read_to_string(h.dir.path().join("netflow.jsonl")).unwrap_or_default();
        assert_eq!(rows.lines().count(), 0, "nothing written");
    }
}
