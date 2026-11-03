//! Lot 275 (C07 1→2) — the drain of the inbound connections.
//!
//! Reads `INBOUND_EVENTS` (`agent-ebpf/src/inbound.rs`): an accept record
//! when `inet_csk_accept` hands a connection to the process that called
//! `accept()`, a close record when `tcp_close` ends one the accept recorded.
//! One ring for both, so a close always comes after its accept. Each record
//! becomes an [`Event::NetInbound`] row with the attribution an outbound
//! flow has ([`FlowTracker`], an instance of its own so inbound flows never
//! evict outbound ones): at the accept the connect-time row (the accepting
//! process, its image, its start), at the close the closed row (byte
//! counters, close reason, the canonical flow id), written to the netflow
//! log with `"inbound": true`. `src_*` is the peer that connected, `dst_*`
//! the local listener's end (the initiator first, as an outbound row).
//!
//! A record carrying accepts the kernel held back (the accepting process's
//! or its user's budget) gives an [`Event::SensorFlood`] too
//! (NN-L-NET-021). The rules of outbound flows do not read these rows (a
//! variant of its own); they are telemetry.

use std::sync::Arc;
use std::time::Instant;

use aya::maps::{ring_buf::RingBuf, MapData};
use common::wire::{held_flags, inbound_kind, NetInboundRaw};
use nn_model::telemetry::NetFlowEvent;
use nn_model::{Event, FloodSource};
use parking_lot::Mutex;
use tracing::{debug, warn};

use crate::net::drain::{NetFlowDb, NETFLOW_SYNC_INTERVAL};
use crate::net::flow_tracker::{FlowTracker, TcpCloseInfo, TcpConnectInfo};
use crate::posture::lineage::AuthSessionTracker;

/// The source's label on the bus, its pump thread's name.
pub const PUMP_LABEL: &str = "net_inbound";

const IPPROTO_TCP: u8 = 6;

/// The socket's kernel address in a correlator (bytes 8..16, little
/// endian): the inbound tracker keys its pending flows as the outbound one.
fn corr_sk(corr: &[u8; 16]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&corr[8..16]);
    u64::from_le_bytes(b)
}

/// The events one record becomes, in bus order, and the closed row to
/// write to the netflow log (if any).
pub fn inbound_events(
    tracker: &mut FlowTracker,
    raw: &NetInboundRaw,
    lineage: &AuthSessionTracker,
) -> (Vec<Event>, Option<NetFlowEvent>) {
    let comm = common::wire::cstr_lossy(&raw.comm).into_owned();
    let remote = nn_model::netaddr::canonical_ip(raw.family, &raw.remote_addr);
    let local = nn_model::netaddr::canonical_ip(raw.family, &raw.local_addr);
    let mut out = Vec::new();
    let mut closed = None;
    match raw.kind {
        inbound_kind::ACCEPT => {
            let info = TcpConnectInfo {
                start_ns: raw.timestamp_ns,
                sk_ptr: corr_sk(&raw.flow_id),
                family: raw.family,
                src_addr: remote,
                src_port: raw.remote_port,
                dst_addr: local,
                dst_port: raw.local_port,
                proto: IPPROTO_TCP,
                pid: raw.pid,
                uid: raw.uid,
                comm: comm.clone(),
                exe: lineage.image_path_at(raw.pid, raw.timestamp_ns),
                proc_start_ns: lineage.start_floor_ns(raw.pid).unwrap_or(0),
            };
            if let Some(row) = tracker.on_tcp_connect(&info) {
                out.push(Event::NetInbound(row));
            }
            let held = if raw.flags & held_flags::TASK != 0 {
                u32::from(raw.held)
            } else {
                0
            };
            let held_uid = if raw.flags & held_flags::UID != 0 {
                u32::from(raw.held_uid)
            } else {
                0
            };
            out.extend(
                nn_model::sensor_floods(
                    FloodSource::Accept,
                    raw.pid,
                    raw.uid,
                    &comm,
                    held,
                    held_uid,
                    raw.timestamp_ns,
                )
                .into_iter()
                .flatten(),
            );
        }
        inbound_kind::CLOSE => {
            let info = TcpCloseInfo {
                end_ns: raw.timestamp_ns,
                corr_id: raw.flow_id,
                src_addr: remote,
                src_port: raw.remote_port,
                bytes_sent: raw.bytes_sent,
                bytes_recv: raw.bytes_recv,
                close_reason: raw.close_reason,
                family: raw.family,
                dst_addr: local,
                dst_port: raw.local_port,
                pid: raw.pid,
                uid: raw.uid,
                comm,
            };
            if let Some(mut row) = tracker.on_tcp_close(&info) {
                if row.exe.is_none() {
                    row.exe = lineage.image_path_at(row.pid, row.start_ns);
                }
                closed = Some(row.clone());
                out.push(Event::NetInbound(row));
            }
        }
        other => debug!(kind = other, "inbound drain: a record of an unknown kind"),
    }
    (out, closed)
}

/// The drain: its ring to empty on each readiness, the rows to the netflow
/// log (one fsync at most every [`NETFLOW_SYNC_INTERVAL`], as the net
/// drain's), the events on the bus.
pub async fn inbound_loop(
    rb: RingBuf<MapData>,
    netflow_db: Option<Arc<Mutex<NetFlowDb>>>,
    lineage: AuthSessionTracker,
    event_tx: crate::sensors::bus::BusSender,
) -> std::io::Result<()> {
    let mut fd = crate::async_fd::register(rb)?;
    let mut tracker = FlowTracker::default();
    let mut reject = crate::sensors::reject::RejectThrottle::new();
    let mut commit_tick = tokio::time::interval(NETFLOW_SYNC_INTERVAL);
    commit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let size = std::mem::size_of::<NetInboundRaw>();
    loop {
        tokio::select! {
            _ = commit_tick.tick() => commit(netflow_db.as_ref()),
            r = fd.readable_mut() => {
                let mut guard = r?;
                let mut events = Vec::new();
                let mut drained = 0u32;
                while let Some(item) = guard.get_inner_mut().next() {
                    drained += 1;
                    let bytes: &[u8] = item.as_ref();
                    let Ok(raw) = bytemuck::try_from_bytes::<NetInboundRaw>(bytes) else {
                        reject.record(PUMP_LABEL, size, bytes.len());
                        continue;
                    };
                    let (evs, closed) = inbound_events(&mut tracker, raw, &lineage);
                    if let (Some(db), Some(row)) = (netflow_db.as_ref(), closed.as_ref()) {
                        if let Err(e) = db.lock().append_inbound(row) {
                            warn!(error = %e, "appending an inbound row to the netflow log failed");
                        }
                    }
                    events.extend(evs);
                }
                guard.clear_ready();
                commit(netflow_db.as_ref());
                for chunk in events.chunks(crate::sensors::bus::BATCH_MAX) {
                    if event_tx.send_batch(chunk.to_vec()).await.is_err() {
                        return Ok(());
                    }
                }
                if drained == 0 {
                    reject.flush_idle(PUMP_LABEL, size);
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    }
}

fn commit(db: Option<&Arc<Mutex<NetFlowDb>>>) {
    if let Some(db) = db {
        if let Err(e) = db.lock().sync_if_due(Instant::now()) {
            warn!(error = %format!("{e:#}"), "netflow log: group commit (fsync) failed; retried");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_model::telemetry::FlowPhase;

    fn raw(kind: u8, ts: u64) -> NetInboundRaw {
        let mut r = NetInboundRaw::zeroed();
        r.kind = kind;
        r.timestamp_ns = ts;
        r.family = 2;
        r.pid = 777;
        r.uid = 33;
        r.comm[..5].copy_from_slice(b"nginx");
        r.remote_addr[..4].copy_from_slice(&[198, 51, 100, 9]);
        r.local_addr[..4].copy_from_slice(&[192, 0, 2, 1]);
        r.remote_port = 50_123;
        r.local_port = 443;
        // the accept's correlator: its time, then the socket
        r.flow_id[..8].copy_from_slice(&1_000u64.to_le_bytes());
        r.flow_id[8..].copy_from_slice(&0xffff_8880_1234_5678u64.to_le_bytes());
        r
    }

    /// An accept then its close: a connect-time row naming the accepting
    /// process and the peer, then the closed row with the counters and the
    /// flow id — the same attribution as an outbound flow's.
    #[test]
    fn an_accept_and_its_close_are_an_inbound_flow() {
        let proc = tempfile::tempdir().unwrap();
        let lineage = AuthSessionTracker::new(proc.path());
        let mut t = FlowTracker::default();
        let (evs, closed) = inbound_events(&mut t, &raw(inbound_kind::ACCEPT, 1_000), &lineage);
        assert!(closed.is_none());
        let [Event::NetInbound(row)] = evs.as_slice() else {
            panic!("{evs:?}");
        };
        assert_eq!(row.phase, FlowPhase::Connect);
        assert_eq!(row.pid, 777);
        assert_eq!(row.comm, "nginx");
        assert_eq!(row.src_addr.to_string(), "198.51.100.9");
        assert_eq!(
            (row.dst_addr.to_string().as_str(), row.dst_port),
            ("192.0.2.1", 443)
        );
        let mut c = raw(inbound_kind::CLOSE, 9_000);
        c.pid = 778; // a worker closes it: the row keeps the acceptor
        c.bytes_sent = 4_000;
        c.bytes_recv = 300;
        c.close_reason = 104;
        let (evs, closed) = inbound_events(&mut t, &c, &lineage);
        let row = closed.expect("closed row");
        assert_eq!(evs.len(), 1);
        assert_eq!(row.phase, FlowPhase::Closed);
        assert_eq!(
            (row.pid, row.bytes_sent, row.bytes_recv, row.close_reason),
            (777, 4_000, 300, 104)
        );
        assert_eq!((row.start_ns, row.end_ns), (1_000, 9_000));
        assert_eq!(row.flow_id.len(), 32);
        assert_eq!(t.pending_len(), 0);
    }

    /// An accept that carries held accepts gives the flood events; a close
    /// with no recorded accept is synthesised (as an outbound close), an
    /// unknown kind gives nothing.
    #[test]
    fn held_accepts_and_odd_records() {
        let proc = tempfile::tempdir().unwrap();
        let lineage = AuthSessionTracker::new(proc.path());
        let mut t = FlowTracker::default();
        let mut a = raw(inbound_kind::ACCEPT, 2_000);
        a.flags = held_flags::TASK | held_flags::UID;
        a.held = 40;
        a.held_uid = 7;
        let (evs, _) = inbound_events(&mut t, &a, &lineage);
        let floods: Vec<_> = evs
            .iter()
            .filter_map(|e| match e {
                Event::SensorFlood {
                    source,
                    held,
                    uid_level,
                    ..
                } => Some((*source, *held, *uid_level)),
                _ => None,
            })
            .collect();
        assert_eq!(
            floods,
            vec![
                (FloodSource::Accept, 40, false),
                (FloodSource::Accept, 7, true)
            ]
        );
        // a held count without its flag is not reported
        let mut b = raw(inbound_kind::ACCEPT, 3_000);
        b.flow_id[8] ^= 1;
        b.held = 9;
        let (evs, _) = inbound_events(&mut t, &b, &lineage);
        assert_eq!(evs.len(), 1);
        let (evs, closed) = inbound_events(&mut t, &raw(9, 4_000), &lineage);
        assert!(evs.is_empty() && closed.is_none());
    }
}
