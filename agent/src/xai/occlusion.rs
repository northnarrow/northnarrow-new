//! Perturbable-unit taxonomy + the occlusion operator (plan §3.1–§3.2).
//!
//! A decision's inputs decompose into *semantic units*, not tokens:
//! every field of the focal [`Event`], every correlated event, and every
//! [`HostContext`] field is one occludable unit. [`enumerate`] lists them
//! (stable order); [`occlude`] returns a neutralised `(focal, context)`
//! copy with exactly one unit removed.
//!
//! ## Occlusion-mode doc-comment (gating question Q1)
//!
//! [`OcclusionMode`] only governs **correlated events**:
//! * [`OcclusionMode::Drop`] (DEFAULT) — remove the event entirely. This
//!   is the legal "but-for" counterfactual ("what if this had not
//!   happened") and is the canonical Article-13 attribution. Prefer it
//!   unless you have a specific reason not to.
//! * [`OcclusionMode::AnonymiseInPlace`] — replace the event with a
//!   same-variant, fully-sentinelled placeholder, preserving its slot
//!   and ordinal position. Prefer this *only* when the model under
//!   analysis is positional-encoding-dominant and dropping would perturb
//!   sequence position as a confound rather than isolate the event's
//!   content.
//!
//! Focal-event fields and host fields are ALWAYS neutralised with a
//! typed neutral sentinel regardless of mode (a scalar field has no
//! "slot" to preserve, and the prompt must stay schema-valid so the
//! model reacts to the *absence of signal*, not to malformed input).

use common::wire::ADDR_LEN;
use common::xai_types::{OcclusionMode, Region};
use common::{Event, FsProtectOperation};

use crate::ade::{EventContext, HostContext};

/// Coarse role of a focal/host field, so the P3 coarse-to-fine driver
/// and bounded-K can prioritise threat-semantic units over pure
/// identifiers without dropping completeness (every field is still a
/// unit — plan §3.1). Correlated events are always `Semantic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    /// Carries threat signal the model attributes over (comm, filename,
    /// query name, destination, operation, host identity…).
    Semantic,
    /// Process/credential identifier (pid/ppid/uid/gid) — kept for
    /// completeness; occluding it is almost always a ~0 counterfactual.
    Identifier,
    /// Monotonic timestamp — kept for completeness; occlusion ~0.
    Temporal,
}

/// Which focal-event field a unit addresses. Exhaustive across all
/// [`Event`] variants; a variant lacking a field simply never emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocalField {
    Comm,
    Filename,
    QueryName,
    QueryType,
    DstAddr,
    DstPort,
    SrcAddr,
    SrcPort,
    Family,
    Flags,
    Operation,
    TargetDev,
    TargetIno,
    Pid,
    Ppid,
    Uid,
    Gid,
    Timestamp,
}

/// Which [`HostContext`] field a unit addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostField {
    Hostname,
    HostId,
    KernelVersion,
    AgentVersion,
}

/// How to neutralise one unit (internal addressing — not the public
/// schema; P4 maps a scored unit onto `common::xai_types::SaliencyEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitAddr {
    Focal(FocalField),
    /// Index into `EventContext.recent_events` at enumerate() time.
    Correlated(usize),
    Host(HostField),
}

/// One occludable input unit.
#[derive(Debug, Clone)]
pub struct PerturbableUnit {
    pub region: Region,
    pub addr: UnitAddr,
    /// Stable id, e.g. `"focal:comm"`, `"correlated:3"`, `"host:hostname"`.
    pub unit_id: String,
    /// Audit-friendly label for the Article-13 dossier.
    pub human_label: String,
    pub field_class: FieldClass,
}

fn focal_unit(f: FocalField, id: &str, label: String, class: FieldClass) -> PerturbableUnit {
    PerturbableUnit {
        region: Region::Focal,
        addr: UnitAddr::Focal(f),
        unit_id: alloc_id("focal", id),
        human_label: label,
        field_class: class,
    }
}

fn alloc_id(prefix: &str, rest: &str) -> String {
    let mut s = String::with_capacity(prefix.len() + 1 + rest.len());
    s.push_str(prefix);
    s.push(':');
    s.push_str(rest);
    s
}

/// Short human tag for a correlated event (variant + its key field).
fn event_kind_label(e: &Event) -> String {
    match e {
        Event::ProcessSpawn { comm, filename, .. } => {
            format!("ProcessSpawn comm={comm} file={filename}")
        }
        Event::FileOpen { comm, filename, .. } => {
            format!("FileOpen comm={comm} file={filename}")
        }
        Event::ExecCheck { comm, filename, .. } => {
            format!("ExecCheck comm={comm} file={filename}")
        }
        Event::TcpConnect {
            comm, dst_port, ..
        } => format!("TcpConnect comm={comm} dport={dst_port}"),
        Event::DnsQuery {
            comm, query_name, ..
        } => format!("DnsQuery comm={comm} q={query_name}"),
        Event::FsProtectDenial {
            comm, operation, ..
        } => format!("FsProtectDenial comm={comm} op={operation:?}"),
    }
}

/// Enumerate every perturbable unit in declaration-stable order:
/// focal fields (variant order below), then correlated events
/// (oldest-first, as stored), then host fields. The order is the unit
/// id namespace contract — `correlated:i` always means
/// `recent_events[i]` at enumerate() time.
pub fn enumerate(focal: &Event, ctx: &EventContext) -> Vec<PerturbableUnit> {
    use FieldClass::*;
    use FocalField as F;

    let mut units: Vec<PerturbableUnit> = Vec::new();

    // ── focal fields (exhaustive per variant) ──
    match focal {
        Event::ProcessSpawn { .. } => {
            units.push(focal_unit(F::Comm, "comm", "focal process comm".into(), Semantic));
            units.push(focal_unit(
                F::Filename,
                "filename",
                "focal executable path".into(),
                Semantic,
            ));
            units.push(focal_unit(F::Pid, "pid", "focal pid".into(), Identifier));
            units.push(focal_unit(F::Ppid, "ppid", "focal ppid".into(), Identifier));
            units.push(focal_unit(F::Uid, "uid", "focal uid".into(), Identifier));
            units.push(focal_unit(F::Gid, "gid", "focal gid".into(), Identifier));
            units.push(focal_unit(F::Timestamp, "ts", "focal timestamp".into(), Temporal));
        }
        Event::FileOpen { .. } => {
            units.push(focal_unit(F::Comm, "comm", "focal process comm".into(), Semantic));
            units.push(focal_unit(
                F::Filename,
                "filename",
                "focal opened path".into(),
                Semantic,
            ));
            units.push(focal_unit(F::Flags, "flags", "focal open flags".into(), Semantic));
            units.push(focal_unit(F::Pid, "pid", "focal pid".into(), Identifier));
            units.push(focal_unit(F::Uid, "uid", "focal uid".into(), Identifier));
            units.push(focal_unit(F::Gid, "gid", "focal gid".into(), Identifier));
            units.push(focal_unit(F::Timestamp, "ts", "focal timestamp".into(), Temporal));
        }
        Event::ExecCheck { .. } => {
            units.push(focal_unit(F::Comm, "comm", "focal process comm".into(), Semantic));
            units.push(focal_unit(
                F::Filename,
                "filename",
                "focal exec-candidate path".into(),
                Semantic,
            ));
            units.push(focal_unit(F::Pid, "pid", "focal pid".into(), Identifier));
            units.push(focal_unit(F::Ppid, "ppid", "focal ppid".into(), Identifier));
            units.push(focal_unit(F::Uid, "uid", "focal uid".into(), Identifier));
            units.push(focal_unit(F::Timestamp, "ts", "focal timestamp".into(), Temporal));
        }
        Event::TcpConnect { .. } => {
            units.push(focal_unit(F::Comm, "comm", "focal process comm".into(), Semantic));
            units.push(focal_unit(
                F::DstAddr,
                "dst_addr",
                "focal destination address".into(),
                Semantic,
            ));
            units.push(focal_unit(
                F::DstPort,
                "dst_port",
                "focal destination port".into(),
                Semantic,
            ));
            units.push(focal_unit(F::SrcAddr, "src_addr", "focal source address".into(), Semantic));
            units.push(focal_unit(F::SrcPort, "src_port", "focal source port".into(), Semantic));
            units.push(focal_unit(F::Family, "family", "focal address family".into(), Semantic));
            units.push(focal_unit(F::Pid, "pid", "focal pid".into(), Identifier));
            units.push(focal_unit(F::Uid, "uid", "focal uid".into(), Identifier));
            units.push(focal_unit(F::Timestamp, "ts", "focal timestamp".into(), Temporal));
        }
        Event::DnsQuery { .. } => {
            units.push(focal_unit(F::Comm, "comm", "focal process comm".into(), Semantic));
            units.push(focal_unit(
                F::QueryName,
                "query_name",
                "focal DNS query name".into(),
                Semantic,
            ));
            units.push(focal_unit(
                F::QueryType,
                "query_type",
                "focal DNS query type".into(),
                Semantic,
            ));
            units.push(focal_unit(
                F::DstAddr,
                "dns_server",
                "focal DNS server address".into(),
                Semantic,
            ));
            units.push(focal_unit(F::Family, "family", "focal address family".into(), Semantic));
            units.push(focal_unit(F::Pid, "pid", "focal pid".into(), Identifier));
            units.push(focal_unit(F::Uid, "uid", "focal uid".into(), Identifier));
            units.push(focal_unit(F::Timestamp, "ts", "focal timestamp".into(), Temporal));
        }
        Event::FsProtectDenial { .. } => {
            units.push(focal_unit(F::Comm, "comm", "focal process comm".into(), Semantic));
            units.push(focal_unit(
                F::Operation,
                "operation",
                "focal denied FS operation".into(),
                Semantic,
            ));
            units.push(focal_unit(
                F::TargetDev,
                "target_dev",
                "focal target device".into(),
                Semantic,
            ));
            units.push(focal_unit(
                F::TargetIno,
                "target_ino",
                "focal target inode".into(),
                Semantic,
            ));
            units.push(focal_unit(F::Pid, "pid", "focal pid".into(), Identifier));
            units.push(focal_unit(F::Uid, "uid", "focal uid".into(), Identifier));
            units.push(focal_unit(F::Timestamp, "ts", "focal timestamp".into(), Temporal));
        }
    }

    // ── correlated events (oldest-first, as stored) ──
    for (i, e) in ctx.recent_events.iter().enumerate() {
        units.push(PerturbableUnit {
            region: Region::Correlated,
            addr: UnitAddr::Correlated(i),
            unit_id: alloc_id("correlated", &i.to_string()),
            human_label: format!("recent #{i}: {}", event_kind_label(e)),
            field_class: Semantic,
        });
    }

    // ── host fields ──
    // Marked Semantic (not Identifier): hostname / kernel_version can
    // legitimately drive a verdict (e.g. a kernel-specific exploit), so
    // they must never be deprioritised out of an Article-13 map.
    units.push(host_unit(HostField::Hostname, "hostname", "host hostname"));
    units.push(host_unit(HostField::HostId, "host_id", "host machine-id"));
    units.push(host_unit(
        HostField::KernelVersion,
        "kernel_version",
        "host kernel version",
    ));
    units.push(host_unit(
        HostField::AgentVersion,
        "agent_version",
        "host agent version",
    ));

    units
}

fn host_unit(h: HostField, id: &str, label: &str) -> PerturbableUnit {
    PerturbableUnit {
        region: Region::Host,
        addr: UnitAddr::Host(h),
        unit_id: alloc_id("host", id),
        human_label: label.into(),
        field_class: FieldClass::Semantic,
    }
}

/// Return a neutralised `(focal, context)` clone with exactly the unit
/// at `addr` occluded. The original inputs are never mutated.
pub fn occlude(
    focal: &Event,
    ctx: &EventContext,
    addr: &UnitAddr,
    mode: OcclusionMode,
) -> (Event, EventContext) {
    match addr {
        UnitAddr::Focal(field) => {
            let mut f = focal.clone();
            neutralise_focal_field(&mut f, *field);
            (f, ctx.clone())
        }
        UnitAddr::Correlated(i) => {
            let mut c = ctx.clone();
            if *i < c.recent_events.len() {
                match mode {
                    OcclusionMode::Drop => {
                        c.recent_events.remove(*i);
                    }
                    OcclusionMode::AnonymiseInPlace => {
                        c.recent_events[*i] = anonymised_clone(&c.recent_events[*i]);
                    }
                }
            }
            (focal.clone(), c)
        }
        UnitAddr::Host(h) => {
            let mut c = ctx.clone();
            neutralise_host_field(&mut c.host_context, *h);
            (focal.clone(), c)
        }
    }
}

const ZERO_ADDR: [u8; ADDR_LEN] = [0u8; ADDR_LEN];

/// Replace one focal field with a typed neutral sentinel. Fields a
/// variant does not have are silently no-ops (the enumerate/occlude
/// pairing guarantees we are only ever called for fields that exist).
fn neutralise_focal_field(e: &mut Event, field: FocalField) {
    use FocalField as F;
    match e {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            gid,
            comm,
            filename,
            timestamp_ns,
        } => match field {
            F::Comm => comm.clear(),
            F::Filename => filename.clear(),
            F::Pid => *pid = 0,
            F::Ppid => *ppid = 0,
            F::Uid => *uid = 0,
            F::Gid => *gid = 0,
            F::Timestamp => *timestamp_ns = 0,
            _ => {}
        },
        Event::FileOpen {
            pid,
            uid,
            gid,
            comm,
            filename,
            flags,
            timestamp_ns,
        } => match field {
            F::Comm => comm.clear(),
            F::Filename => filename.clear(),
            F::Flags => *flags = 0,
            F::Pid => *pid = 0,
            F::Uid => *uid = 0,
            F::Gid => *gid = 0,
            F::Timestamp => *timestamp_ns = 0,
            _ => {}
        },
        Event::ExecCheck {
            pid,
            ppid,
            uid,
            comm,
            filename,
            timestamp_ns,
        } => match field {
            F::Comm => comm.clear(),
            F::Filename => filename.clear(),
            F::Pid => *pid = 0,
            F::Ppid => *ppid = 0,
            F::Uid => *uid = 0,
            F::Timestamp => *timestamp_ns = 0,
            _ => {}
        },
        Event::TcpConnect {
            pid,
            uid,
            comm,
            family,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            timestamp_ns,
        } => match field {
            F::Comm => comm.clear(),
            F::DstAddr => *dst_addr = ZERO_ADDR,
            F::DstPort => *dst_port = 0,
            F::SrcAddr => *src_addr = ZERO_ADDR,
            F::SrcPort => *src_port = 0,
            F::Family => *family = 0,
            F::Pid => *pid = 0,
            F::Uid => *uid = 0,
            F::Timestamp => *timestamp_ns = 0,
            _ => {}
        },
        Event::DnsQuery {
            pid,
            uid,
            comm,
            query_name,
            query_type,
            dns_server,
            family,
            timestamp_ns,
        } => match field {
            F::Comm => comm.clear(),
            F::QueryName => query_name.clear(),
            F::QueryType => *query_type = 0,
            F::DstAddr => *dns_server = ZERO_ADDR,
            F::Family => *family = 0,
            F::Pid => *pid = 0,
            F::Uid => *uid = 0,
            F::Timestamp => *timestamp_ns = 0,
            _ => {}
        },
        Event::FsProtectDenial {
            pid,
            uid,
            comm,
            target_dev,
            target_ino,
            operation,
            timestamp_ns,
        } => match field {
            F::Comm => comm.clear(),
            // `Unknown(0)` is the forward-compat "unrecognised" sentinel
            // — a semantically empty operation, not a real FS op.
            F::Operation => *operation = FsProtectOperation::Unknown(0),
            F::TargetDev => *target_dev = 0,
            F::TargetIno => *target_ino = 0,
            F::Pid => *pid = 0,
            F::Uid => *uid = 0,
            F::Timestamp => *timestamp_ns = 0,
            _ => {}
        },
    }
}

/// A same-variant clone with every semantic field sentinelled — used by
/// [`OcclusionMode::AnonymiseInPlace`] to keep the slot/position while
/// removing the event's content.
fn anonymised_clone(e: &Event) -> Event {
    let mut c = e.clone();
    for f in [
        FocalField::Comm,
        FocalField::Filename,
        FocalField::QueryName,
        FocalField::QueryType,
        FocalField::DstAddr,
        FocalField::DstPort,
        FocalField::SrcAddr,
        FocalField::SrcPort,
        FocalField::Family,
        FocalField::Flags,
        FocalField::Operation,
        FocalField::TargetDev,
        FocalField::TargetIno,
    ] {
        neutralise_focal_field(&mut c, f);
    }
    c
}

fn neutralise_host_field(h: &mut HostContext, field: HostField) {
    match field {
        HostField::Hostname => h.hostname.clear(),
        HostField::HostId => h.host_id.clear(),
        HostField::KernelVersion => h.kernel_version.clear(),
        HostField::AgentVersion => h.agent_version.clear(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ps() -> Event {
        Event::ProcessSpawn {
            pid: 7,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "miner".to_string(),
            filename: "/tmp/x".to_string(),
            timestamp_ns: 42,
        }
    }
    fn dns(q: &str) -> Event {
        Event::DnsQuery {
            pid: 7,
            uid: 0,
            comm: "curl".to_string(),
            query_name: q.to_string(),
            query_type: 1,
            dns_server: [0u8; ADDR_LEN],
            family: 2,
            timestamp_ns: 1,
        }
    }
    fn ctx(recent: Vec<Event>) -> EventContext {
        EventContext {
            recent_events: recent,
            host_context: HostContext {
                hostname: "h".into(),
                host_id: "id".into(),
                kernel_version: "6.8".into(),
                agent_version: "0.0.1".into(),
            },
        }
    }

    #[test]
    fn enumerate_counts_focal_plus_correlated_plus_host() {
        let u = enumerate(&ps(), &ctx(vec![dns("a"), dns("b")]));
        // ProcessSpawn = 7 focal, +2 correlated, +4 host = 13.
        assert_eq!(u.len(), 13);
        assert_eq!(u[0].unit_id, "focal:comm");
        assert!(u.iter().any(|x| x.unit_id == "correlated:1"));
        assert!(u.iter().any(|x| x.unit_id == "host:agent_version"));
    }

    #[test]
    fn focal_field_occlusion_is_surgical() {
        let (f, _) = occlude(
            &ps(),
            &ctx(vec![]),
            &UnitAddr::Focal(FocalField::Comm),
            OcclusionMode::Drop,
        );
        match f {
            Event::ProcessSpawn { comm, filename, .. } => {
                assert!(comm.is_empty(), "comm sentinelled");
                assert_eq!(filename, "/tmp/x", "other fields untouched");
            }
            _ => panic!("variant changed"),
        }
    }

    #[test]
    fn drop_mode_removes_the_correlated_event() {
        let c = ctx(vec![dns("keep"), dns("c2.evil.zz"), dns("keep2")]);
        let (_, c2) = occlude(&ps(), &c, &UnitAddr::Correlated(1), OcclusionMode::Drop);
        assert_eq!(c2.recent_events.len(), 2);
        assert!(!c2.recent_events.iter().any(|e| matches!(
            e, Event::DnsQuery { query_name, .. } if query_name.contains("c2.evil")
        )));
    }

    #[test]
    fn anonymise_mode_keeps_slot_but_strips_content() {
        let c = ctx(vec![dns("c2.evil.zz")]);
        let (_, c2) = occlude(
            &ps(),
            &c,
            &UnitAddr::Correlated(0),
            OcclusionMode::AnonymiseInPlace,
        );
        assert_eq!(c2.recent_events.len(), 1, "slot preserved");
        match &c2.recent_events[0] {
            Event::DnsQuery { query_name, .. } => {
                assert!(query_name.is_empty(), "content stripped, variant kept");
            }
            _ => panic!("variant must be preserved by anonymise-in-place"),
        }
    }

    #[test]
    fn host_field_occlusion_is_surgical() {
        let (_, c2) = occlude(
            &ps(),
            &ctx(vec![]),
            &UnitAddr::Host(HostField::Hostname),
            OcclusionMode::Drop,
        );
        assert!(c2.host_context.hostname.is_empty());
        assert_eq!(c2.host_context.kernel_version, "6.8");
    }
}
