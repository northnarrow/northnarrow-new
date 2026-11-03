//! Lot 275 (NN-L-NET-028): nn-core's resolved table on the Linux host — the
//! DNS response pump's ingest with it — and the judgement the connect pump
//! (TCP) and the net drain (UDP) write on a flow's row
//! ([`judge`]).

use std::net::IpAddr;
use std::sync::Arc;

use nn_core::posture::lineage::AsOf;
use nn_model::telemetry::DnsResolution;

pub use nn_core::net::resolved::*;

use crate::net::dns_ingest::DnsIngest;

/// [`nn_core::net::resolved::ResolvedTable`] with the DNS response pump's
/// ingest: a connect waits for the responses received before it.
pub type ResolvedTable = nn_core::net::resolved::ResolvedTable<DnsIngest>;

/// Held by the DNS response pump while it runs: the connects wait for its
/// passes only then, and the table knows since when the sensor runs.
#[derive(Debug)]
pub struct ResolvedClaim(Arc<ResolvedTable>);

impl ResolvedClaim {
    pub fn new(table: Arc<ResolvedTable>, now_ns: u64) -> Self {
        table.ingest().set_pump(true);
        table.set_sensor_since(now_ns.max(1));
        Self(table)
    }
}

impl Drop for ResolvedClaim {
    fn drop(&mut self) {
        self.0.set_sensor_since(0);
        self.0.ingest().set_pump(false);
    }
}

/// Held by a pump whose ring a record's attribution waits on through an
/// ingest of its own (the TLS ClientHello pump's).
#[derive(Debug)]
pub struct PumpClaim(Arc<DnsIngest>);

impl PumpClaim {
    pub fn new(ingest: Arc<DnsIngest>) -> Self {
        ingest.set_pump(true);
        Self(ingest)
    }
}

impl Drop for PumpClaim {
    fn drop(&mut self) {
        self.0.set_pump(false);
    }
}

/// What the DNS evidence says of a connect to `dst` at `ts_ns` by `pid`
/// (which started at `proc_start_ns`, 0 when `/proc` no longer shows it):
/// - `NotJudged` for a destination that is not public;
/// - `Unknown` while the DNS response sensor does not run, and for a
///   process older than the sensor that the evidence does not bind (it may
///   have resolved the address before the sensor watched);
/// - otherwise [`ResolvedTable::check`] over the process and its lineage as
///   the spawn cache knows it at the connect.
pub fn judge(
    table: &ResolvedTable,
    lineage: &crate::posture::lineage::AuthSessionTracker,
    pid: u32,
    proc_start_ns: u64,
    dst: IpAddr,
    ts_ns: u64,
) -> DnsResolution {
    if !nn_model::netaddr::is_public(dst) {
        return DnsResolution::NotJudged;
    }
    let Some(since) = table.sensor_since() else {
        return DnsResolution::Unknown;
    };
    let as_of = AsOf::judged(ts_ns);
    // a process `/proc` no longer shows (a quick connect and exit): its
    // start as the spawn cache knows it
    let mut start = proc_start_ns;
    let mut walked: Option<Vec<(u32, u64)>> = None;
    if start == 0 {
        let w = lineage.lineage_starts(pid, as_of);
        start = w.first().filter(|(p, _)| *p == pid).map_or(0, |(_, s)| *s);
        walked = Some(w);
    }
    let r = table.check(pid, start, dst, ts_ns, || {
        let w = walked.unwrap_or_else(|| lineage.lineage_starts(pid, as_of));
        w.into_iter().filter(|(p, _)| *p != pid).collect()
    });
    if r.not_resolved_by_lineage() && (start == 0 || start < since) {
        DnsResolution::Unknown
    } else {
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::lineage::AuthSessionTracker;
    use std::net::Ipv4Addr;

    const S: u64 = 1_000_000_000;
    const C2: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));

    fn table() -> Arc<ResolvedTable> {
        Arc::new(ResolvedTable::default())
    }

    #[test]
    fn only_public_destinations_are_judged_and_only_while_the_sensor_runs() {
        let t = table();
        let proc = tempfile::tempdir().unwrap();
        let lineage = AuthSessionTracker::new(proc.path());
        let lan = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(judge(&t, &lineage, 42, 5 * S, lan, 10 * S), DnsResolution::NotJudged);
        // no sensor: unknown
        assert_eq!(judge(&t, &lineage, 42, 5 * S, C2, 10 * S), DnsResolution::Unknown);
        let claim = ResolvedClaim::new(Arc::clone(&t), 2 * S);
        assert!(t.ingest().covers(0));
        // started after the sensor, nothing resolved: unresolved
        assert_eq!(judge(&t, &lineage, 42, 5 * S, C2, 10 * S), DnsResolution::Unresolved);
        // started before it: unknown
        assert_eq!(judge(&t, &lineage, 42, S, C2, 10 * S), DnsResolution::Unknown);
        // start unknown, not in the spawn cache: unknown
        assert_eq!(judge(&t, &lineage, 42, 0, C2, 10 * S), DnsResolution::Unknown);
        // gone from /proc, its start from the spawn cache
        lineage.ingest_exec(43, 1, "/usr/bin/curl", &[], 4 * S, 3 * S, 0);
        let got = judge(&t, &lineage, 43, 0, C2, 10 * S);
        assert!(matches!(got, DnsResolution::Unresolved | DnsResolution::Unknown), "{got:?}");
        // resolved by the process: lineage
        t.on_answer(&Answer {
            pid: 42,
            ts_ns: 6 * S,
            qname: "c2.example",
            records: &[Record::Addr {
                name: "c2.example".into(),
                ttl: 60,
                addr: C2,
            }],
        });
        assert_eq!(judge(&t, &lineage, 42, 5 * S, C2, 10 * S), DnsResolution::Lineage);
        drop(claim);
        assert_eq!(t.sensor_since(), None);
        assert_eq!(judge(&t, &lineage, 44, 5 * S, C2, 10 * S), DnsResolution::Unknown);
    }
}
