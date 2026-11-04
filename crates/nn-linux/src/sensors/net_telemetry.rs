//! Lot 275 (C07 1→2): the attach of the inbound-connection, DNS response
//! and TLS ClientHello sensors (`agent-ebpf/src/{inbound, dns_answer,
//! tls_hello}.rs`), and the pumps of the last two.
//!
//! The fexit programs whose function changed its parameter count across
//! the supported kernels come in one variant per count
//! ([`ARITY_VARIANTS`]); the attach takes the one built for this kernel's
//! BTF (`btf_revalidate::ResolvedOffsets::param_count`) — never a guess:
//! a count no variant matches leaves the sensor off, signed. Every sensor
//! here is soft: one that does not attach is a signed degradation, and the
//! agent runs without it (its contract: blind).
//!
//! The DNS response pump decodes each response through the parse worker
//! (R14b: the core parses no DNS bytes) and feeds the resolved table
//! (`crate::net::resolved`) before the event goes out; it marks its passes
//! on the table's ingest, so a connect judged by NN-L-NET-028 waits for
//! the responses received before it. The TLS pump fingerprints each hello
//! through the worker, attaches the fingerprint to the pending flow (its
//! snapshots and closed row carry it) and marks its passes on its own
//! ingest, which the net drain's closes wait on.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{ring_buf::RingBuf, MapData},
    programs::{FEntry, FExit},
    Btf, Ebpf,
};
use common::wire::{answer_flags, held_flags, tls_flags, DnsAnswerRaw, TlsHelloRaw};
use nn_model::telemetry::{DnsAnswerEvent, TlsFingerprint, TlsHelloEvent, TlsHelloOutcome};
use nn_model::{Event, FloodSource};
use nn_proto::ipc::{DnsAnswersOut, DnsRecordOut, SniOut, TlsOut};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::boot::manifest::{AttachPoints, Took};
use crate::net::dns_ingest::DnsIngest;
use crate::net::flow_tracker::FlowTracker;
use crate::net::resolved::{Answer, Record, ResolvedTable};
use crate::posture::lineage::AuthSessionTracker;
use crate::sensors::bus::BusSender;
use crate::sensors::pump::{PumpThread, POLL_MS};
use crate::sensors::reject::RejectThrottle;
use crate::worker::parse::ParseClient;

/// The DNS response pump's label (a source of the bus).
pub const DNS_ANSWER_LABEL: &str = "dns_answer";
/// The TLS ClientHello pump's label.
pub const TLS_HELLO_LABEL: &str = "tls_hello";

/// `(program, traced function, the parameter count it is built for)`.
pub const ARITY_VARIANTS: &[(&str, &str, usize)] = &[
    ("inbound_accept_ret4", "inet_csk_accept", 4),
    ("inbound_accept_ret2", "inet_csk_accept", 2),
    ("dns_answer_v4_ret6", "udp_recvmsg", 6),
    ("dns_answer_v4_ret5", "udp_recvmsg", 5),
    ("dns_answer_v6_ret6", "udpv6_recvmsg", 6),
    ("dns_answer_v6_ret5", "udpv6_recvmsg", 5),
];

/// The variant of `func`'s fexit built for `params` parameters.
pub fn variant_for(func: &str, params: usize) -> Option<&'static str> {
    ARITY_VARIANTS
        .iter()
        .find(|(_, f, n)| *f == func && *n == params)
        .map(|(p, _, _)| *p)
}

/// Why `program` is not loaded on a kernel whose `func` has `params`
/// parameters (`None`: it is the one; the verifier check reads it).
pub fn other_arity(program: &str, params: Option<usize>) -> Option<String> {
    let (_, func, n) = ARITY_VARIANTS.iter().find(|(p, _, _)| *p == program)?;
    match params {
        Some(k) if k == *n => None,
        Some(k) => Some(format!(
            "built for {func} with {n} parameters; this kernel's has {k} (another variant is \
             loaded)"
        )),
        None => Some(format!("this kernel's BTF has no {func}")),
    }
}

/// This kernel's parameter count of `func`, from the boot's BTF resolution.
fn params_of(func: &str) -> Option<usize> {
    crate::anti_tamper::btf_revalidate::resolved()?.param_count(func)
}

fn attach_fexit_to(ebpf: &mut Ebpf, program: &str, func: &str, btf: &Btf) -> Result<()> {
    let prog: &mut FExit = ebpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program {program} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not an fexit"))?;
    prog.load(func, btf)
        .with_context(|| format!("verifier rejected fexit `{program}` on {func}"))?;
    prog.attach()
        .with_context(|| format!("attaching fexit `{program}` to {func}"))?;
    Ok(())
}

/// The fexit of `func` built for this kernel, attached.
fn attach_by_arity(ebpf: &mut Ebpf, func: &str, btf: &Btf) -> Result<&'static str> {
    let n = params_of(func)
        .ok_or_else(|| anyhow!("{func}: not in this kernel's BTF (or no BTF resolution)"))?;
    let program = variant_for(func, n)
        .ok_or_else(|| anyhow!("{func} has {n} parameters: no program is built for that"))?;
    attach_fexit_to(ebpf, program, func, btf)?;
    Ok(program)
}

/// What attached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Attached {
    pub inbound: bool,
    pub dns_answer: bool,
    pub tls_hello: bool,
}

/// Attach the three sensors (after the net flows': `tcp_close` records an
/// accepted socket's close), each noted for the manifest and each failure
/// signed.
pub fn attach(ebpf: &mut Ebpf, btf: &Btf, points: &AttachPoints) -> Attached {
    use crate::sensors::contract::attach as a;
    let mut out = Attached::default();
    match attach_by_arity(ebpf, "inet_csk_accept", btf) {
        Ok(p) => {
            info!(program = p, "inbound connection sensor attached");
            points.note("net_inbound", a::NET_INBOUND, Took::Whole);
            out.inbound = true;
        }
        Err(e) => {
            let why = format!("{e:#}");
            warn!(error = %why, "inbound connection sensor NOT attached — accepted connections are not observed");
            points.note("net_inbound", &format!("not attached: {why}"), Took::Absent);
            crate::boot::degradation::report(
                "net_inbound",
                &format!("the inbound connection sensor is not attached ({why}): accepted connections are not observed"),
            );
        }
    }
    let v4 = attach_by_arity(ebpf, "udp_recvmsg", btf);
    let v6 = attach_by_arity(ebpf, "udpv6_recvmsg", btf);
    match (&v4, &v6) {
        (Ok(_), Ok(_)) => {
            info!("DNS response sensor attached (udp_recvmsg + udpv6_recvmsg)");
            points.note("dns_answer", a::DNS_ANSWER, Took::Whole);
            out.dns_answer = true;
        }
        (Ok(_), Err(e)) => {
            let why = format!("udpv6_recvmsg ({e:#}): DNS responses over IPv6 are not observed");
            warn!(error = %why, "DNS response sensor partly attached");
            points.note(
                "dns_answer",
                a::DNS_ANSWER_V4,
                Took::Partial {
                    missing: vec![why.clone()],
                },
            );
            crate::boot::degradation::report("dns_answer", &why);
            out.dns_answer = true;
        }
        (Err(e), _) => {
            let why = format!("{e:#}");
            warn!(error = %why, "DNS response sensor NOT attached — NN-L-NET-028 judges every connect unknown");
            points.note("dns_answer", &format!("not attached: {why}"), Took::Absent);
            crate::boot::degradation::report(
                "dns_answer",
                &format!("the DNS response sensor is not attached ({why}): no response is observed, NN-L-NET-028 judges every connect unknown"),
            );
        }
    }
    match attach_fentry(ebpf, "tls_client_hello", "tcp_sendmsg", btf) {
        Ok(()) => {
            info!("TLS ClientHello sensor attached (fentry tcp_sendmsg)");
            points.note("tls_hello", a::TLS_HELLO, Took::Whole);
            out.tls_hello = true;
        }
        Err(e) => {
            let why = format!("{e:#}");
            warn!(error = %why, "TLS ClientHello sensor NOT attached — no JA3/JA4, NN-L-NET-003 cannot match");
            points.note("tls_hello", &format!("not attached: {why}"), Took::Absent);
            crate::boot::degradation::report(
                "tls_hello",
                &format!("the TLS ClientHello sensor is not attached ({why}): no fingerprint is produced, NN-L-NET-003 cannot match"),
            );
        }
    }
    out
}

fn attach_fentry(ebpf: &mut Ebpf, program: &str, func: &str, btf: &Btf) -> Result<()> {
    let prog: &mut FEntry = ebpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program {program} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not an fentry"))?;
    prog.load(func, btf)
        .with_context(|| format!("verifier rejected fentry `{program}` on {func}"))?;
    prog.attach()
        .with_context(|| format!("attaching fentry `{program}` to {func}"))?;
    Ok(())
}

/// What a pump's passes read since its last summary line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassStats {
    /// Records read.
    pub records: u64,
    /// Decoded by the parse worker (a response with its question, a
    /// complete hello).
    pub decoded: u64,
    /// The last decoded record, for the summary (escaped when logged).
    pub last: Option<String>,
}

/// How often a pump says what it read (INFO, only when it read anything):
/// the journal shows the sensor alive without a line per record.
pub const SUMMARY_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

// ── the DNS response pump ─────────────────────────────────────────────

/// The event of one response record, and the table's input, from the
/// worker's decode (`None`: not decoded — the worker did not answer, or
/// the bytes are no response).
pub fn answer_event(
    raw: &DnsAnswerRaw,
    decoded: Option<&DnsAnswersOut>,
    exe: Option<String>,
) -> (DnsAnswerEvent, Vec<Record>) {
    let mut records = Vec::new();
    let mut addrs = Vec::new();
    let mut cnames = Vec::new();
    let mut ttl: Option<u32> = None;
    if let Some(d) = decoded {
        for r in &d.records {
            match r {
                DnsRecordOut::A { name, ttl: t, addr } => {
                    let a = std::net::IpAddr::from(*addr);
                    addrs.push(a);
                    ttl = Some(ttl.map_or(*t, |m| m.min(*t)));
                    records.push(Record::Addr {
                        name: name.clone(),
                        ttl: *t,
                        addr: a,
                    });
                }
                DnsRecordOut::Aaaa { name, ttl: t, addr } => {
                    let a = nn_model::netaddr::canonical(std::net::IpAddr::from(*addr));
                    addrs.push(a);
                    ttl = Some(ttl.map_or(*t, |m| m.min(*t)));
                    records.push(Record::Addr {
                        name: name.clone(),
                        ttl: *t,
                        addr: a,
                    });
                }
                DnsRecordOut::Cname {
                    name,
                    ttl: t,
                    target,
                } => {
                    cnames.push(target.clone());
                    records.push(Record::Cname {
                        name: name.clone(),
                        ttl: *t,
                        target: target.clone(),
                    });
                }
            }
        }
    }
    let ev = DnsAnswerEvent {
        timestamp_ns: raw.timestamp_ns,
        pid: raw.pid,
        uid: raw.uid,
        comm: common::wire::cstr_lossy(&raw.comm).into_owned(),
        exe,
        server: nn_model::netaddr::canonical_ip(raw.family, &raw.server),
        server_port: raw.server_port,
        query_name: decoded.map(|d| d.qname.clone()),
        query_type: decoded.map_or(0, |d| d.qtype),
        rcode: decoded.map_or(0, |d| d.rcode),
        addrs,
        cnames,
        ttl_secs: ttl.unwrap_or(0),
        datagram_len: raw.datagram_len,
        truncated: raw.flags & answer_flags::TRUNCATED != 0 || decoded.is_some_and(|d| !d.complete),
    };
    (ev, records)
}

/// The floods a record carries (its process's held count, its user's).
/// `(held, held_uid)` are the record's counts, read only with their flag.
fn floods(
    source: FloodSource,
    raw_flags: u8,
    (held, held_uid): (u16, u16),
    pid: u32,
    uid: u32,
    comm: &str,
    ts: u64,
) -> impl Iterator<Item = Event> {
    let h = if raw_flags & held_flags::TASK != 0 {
        u32::from(held)
    } else {
        0
    };
    let hu = if raw_flags & held_flags::UID != 0 {
        u32::from(held_uid)
    } else {
        0
    };
    nn_model::sensor_floods(source, pid, uid, comm, h, hu, ts)
        .into_iter()
        .flatten()
}

/// One pass over the DNS response ring: each record decoded, the table
/// fed, its events into `outbox`. Returns the records read.
#[allow(clippy::too_many_arguments)]
fn answer_pass(
    ring: &mut RingBuf<MapData>,
    table: &ResolvedTable,
    lineage: &AuthSessionTracker,
    parse: &ParseClient,
    losses: &mut crate::sensors::ring_drops::LossWatch,
    reject: &mut RejectThrottle,
    outbox: &mut VecDeque<Event>,
    stats: &mut PassStats,
) -> u32 {
    // review of #495, D3: a response lost before this pass (the ring full,
    // a process's or a user's budget) leaves every process's evidence
    // incomplete, whoever lost it
    if losses.grew() {
        table.note_undecoded(crate::net::dns_ingest::monotonic_ns());
    }
    let size = std::mem::size_of::<DnsAnswerRaw>();
    let mut raws: Vec<DnsAnswerRaw> = Vec::new();
    let mut drained = 0u32;
    while let Some(item) = ring.next() {
        drained += 1;
        let bytes: &[u8] = item.as_ref();
        match bytemuck::try_from_bytes::<DnsAnswerRaw>(bytes) {
            Ok(r) => raws.push(*r),
            Err(_) => reject.record(DNS_ANSWER_LABEL, size, bytes.len()),
        }
    }
    for raw in &raws {
        let bytes = captured_payload(raw);
        // `None`: the worker did not answer; `Some(None)`: no DNS response
        let decoded = if bytes.is_empty() {
            Some(None)
        } else {
            parse.dns_answers(bytes)
        };
        let exe = lineage.image_at(raw.pid, raw.timestamp_ns);
        outbox.extend(ingest_answer(raw, decoded, exe, table, stats));
    }
    drained
}

/// The bytes of a response record the sensor copied: its payload up to
/// `captured` (review of #495, RA5: never past it).
fn captured_payload(raw: &DnsAnswerRaw) -> &[u8] {
    let n = usize::from(raw.captured).min(raw.payload.len());
    &raw.payload[..n]
}

/// One response record: the table fed (its records bound; an undecoded
/// one degrading the evidence; held records noted), its events.
/// `decoded`: `None` when the worker did not answer, `Some(None)` for
/// bytes that are no DNS response (or none read).
fn ingest_answer(
    raw: &DnsAnswerRaw,
    decoded: Option<Option<DnsAnswersOut>>,
    exe: Option<String>,
    table: &ResolvedTable,
    stats: &mut PassStats,
) -> Vec<Event> {
    let worker_answered = decoded.is_some();
    let decoded = decoded.flatten();
    let (ev, records) = answer_event(raw, decoded.as_ref(), exe);
    stats.records += 1;
    match &ev.query_name {
        Some(q) => {
            stats.decoded += 1;
            stats.last = Some(format!(
                "{q} -> {} address(es), rcode {}",
                ev.addrs.len(),
                ev.rcode
            ));
            // review of #495: a response cut (the sensor's cap, the
            // server's TC bit, a malformed record) answers nothing (D1); a
            // system resolver's counts host-wide, any other process's for
            // itself only (D4)
            table.on_answer(&Answer {
                pid: raw.pid,
                ts_ns: raw.timestamp_ns,
                qname: q,
                records: &records,
                complete: !ev.truncated,
                resolver: crate::net::resolved::is_system_resolver(ev.exe.as_deref(), raw.uid),
            });
        }
        // the worker did not answer: what the response named is not known
        None if !worker_answered => table.note_undecoded(raw.timestamp_ns),
        // a datagram from port 53 whose bytes were not read: its
        // receiver's evidence is incomplete
        None if raw.flags & answer_flags::UNREAD != 0 => table.note_held(raw.pid, raw.timestamp_ns),
        // no DNS response: no evidence either way
        None => {}
    }
    // review of #495, D3: a user's held records leave every process's
    // evidence incomplete (the count rides on whichever record of the user
    // comes next); a process's, its own lineage's
    if raw.flags & held_flags::UID != 0 {
        table.note_undecoded(raw.timestamp_ns);
    } else if raw.flags & held_flags::TASK != 0 {
        table.note_held(raw.pid, raw.timestamp_ns);
    }
    let comm = ev.comm.clone();
    let mut out = vec![Event::DnsAnswer(ev)];
    out.extend(floods(
        FloodSource::DnsAnswer,
        raw.flags,
        (raw.held, raw.held_uid),
        raw.pid,
        raw.uid,
        &comm,
        raw.timestamp_ns,
    ));
    out
}

/// The DNS response pump (a thread of its own, a source of the bus).
/// `attached`: the sensor's programs attached. Only then does the table say
/// since when the sensor runs (NN-L-NET-028 judges the connects; without
/// it every one is unknown) and do the connects wait for its passes.
#[allow(clippy::too_many_arguments)]
pub fn spawn_dns_answer_pump(
    rb: RingBuf<MapData>,
    table: Arc<ResolvedTable>,
    attached: bool,
    lineage: AuthSessionTracker,
    parse: ParseClient,
    mut losses: crate::sensors::ring_drops::LossWatch,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> Result<PumpThread> {
    let claim = crate::net::resolved::ResolvedClaim::if_attached(
        &table,
        attached,
        crate::net::dns_ingest::monotonic_ns(),
    );
    let tx = tx.for_source("dns_answer");
    let rt = rt.clone();
    PumpThread::spawn("dns_answer", move |stop| {
        let _claim = claim;
        let ingest_owner = Arc::clone(&table);
        rt.block_on(ingest_pump(
            rb,
            ingest_owner.ingest(),
            tx,
            stop,
            DNS_ANSWER_LABEL,
            std::mem::size_of::<DnsAnswerRaw>(),
            |ring, reject, outbox, stats| {
                answer_pass(
                    ring,
                    &table,
                    &lineage,
                    &parse,
                    &mut losses,
                    reject,
                    outbox,
                    stats,
                )
            },
        ))
    })
    .context("starting the dns_answer pump's thread")
}

// ── the TLS ClientHello pump ──────────────────────────────────────────

/// The event of one hello record from the worker's answer (`None`: the
/// worker did not answer).
pub fn hello_event(raw: &TlsHelloRaw, out: Option<&TlsOut>, exe: Option<String>) -> TlsHelloEvent {
    let (outcome, fingerprint) = match out {
        None => (TlsHelloOutcome::Undecoded, None),
        Some(TlsOut::Incomplete) => (TlsHelloOutcome::Incomplete, None),
        Some(TlsOut::Invalid) => (TlsHelloOutcome::Invalid, None),
        Some(TlsOut::Complete {
            ja3,
            ja4,
            sni,
            alpn,
        }) => (
            TlsHelloOutcome::Complete,
            Some(TlsFingerprint {
                ja3: ja3.clone(),
                // not carried by the worker's answer
                ja3_raw: String::new(),
                ja4: ja4.clone(),
                sni: match sni {
                    SniOut::Host(h) => Some(h.clone()),
                    SniOut::Absent | SniOut::NonConforming => None,
                },
                alpn: alpn.clone(),
            }),
        ),
    };
    TlsHelloEvent {
        timestamp_ns: raw.timestamp_ns,
        pid: raw.pid,
        uid: raw.uid,
        comm: common::wire::cstr_lossy(&raw.comm).into_owned(),
        exe,
        family: raw.family,
        dst_addr: nn_model::netaddr::canonical_ip(raw.family, &raw.dst_addr),
        dst_port: raw.dst_port,
        flow_start_ns: FlowTracker::corr_start_ns(&raw.flow_id),
        outcome,
        fingerprint,
        send_len: raw.send_len,
        truncated: raw.flags & tls_flags::TRUNCATED != 0,
    }
}

fn hello_pass(
    ring: &mut RingBuf<MapData>,
    flow_tracker: &Mutex<FlowTracker>,
    lineage: &AuthSessionTracker,
    parse: &ParseClient,
    reject: &mut RejectThrottle,
    outbox: &mut VecDeque<Event>,
    stats: &mut PassStats,
) -> u32 {
    let size = std::mem::size_of::<TlsHelloRaw>();
    let mut raws: Vec<Box<TlsHelloRaw>> = Vec::new();
    let mut drained = 0u32;
    while let Some(item) = ring.next() {
        drained += 1;
        let bytes: &[u8] = item.as_ref();
        match bytemuck::try_from_bytes::<TlsHelloRaw>(bytes) {
            Ok(r) => raws.push(Box::new(*r)),
            Err(_) => reject.record(TLS_HELLO_LABEL, size, bytes.len()),
        }
    }
    for raw in &raws {
        let n = usize::from(raw.captured).min(raw.data.len());
        let out = if n == 0 {
            None
        } else {
            parse.client_hello(&raw.data[..n])
        };
        let exe = lineage.image_at(raw.pid, raw.timestamp_ns);
        outbox.extend(ingest_hello(raw, out.as_ref(), exe, flow_tracker, stats));
    }
    drained
}

/// One hello record: its fingerprint attached to its pending flow, its
/// events.
fn ingest_hello(
    raw: &TlsHelloRaw,
    out: Option<&TlsOut>,
    exe: Option<String>,
    flow_tracker: &Mutex<FlowTracker>,
    stats: &mut PassStats,
) -> Vec<Event> {
    let ev = hello_event(raw, out, exe);
    stats.records += 1;
    if let Some(fp) = &ev.fingerprint {
        stats.decoded += 1;
        stats.last = Some(format!(
            "{}:{} ja3 {} ja4 {} sni {}",
            ev.dst_addr,
            ev.dst_port,
            fp.ja3,
            fp.ja4,
            fp.sni.as_deref().unwrap_or("-")
        ));
        if raw.flow_id != [0u8; 16] {
            flow_tracker
                .lock()
                .attach_tls_pending(&raw.flow_id, fp.clone());
        }
    }
    let comm = ev.comm.clone();
    let mut evs = vec![Event::TlsClientHello(ev)];
    evs.extend(floods(
        FloodSource::TlsHello,
        raw.flags,
        (raw.held, raw.held_uid),
        raw.pid,
        raw.uid,
        &comm,
        raw.timestamp_ns,
    ));
    evs
}

/// The TLS ClientHello pump (a thread of its own, a source of the bus).
/// `attached`: the sensor's program attached; only then do the closes wait
/// for its passes.
#[allow(clippy::too_many_arguments)]
pub fn spawn_tls_pump(
    rb: RingBuf<MapData>,
    ingest: Arc<DnsIngest>,
    attached: bool,
    flow_tracker: Arc<Mutex<FlowTracker>>,
    lineage: AuthSessionTracker,
    parse: ParseClient,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> Result<PumpThread> {
    let claim = crate::net::resolved::PumpClaim::if_attached(&ingest, attached);
    let tx = tx.for_source("tls_hello");
    let rt = rt.clone();
    PumpThread::spawn("tls_hello", move |stop| {
        let _claim = claim;
        rt.block_on(ingest_pump(
            rb,
            &ingest,
            tx,
            stop,
            TLS_HELLO_LABEL,
            std::mem::size_of::<TlsHelloRaw>(),
            |ring, reject, outbox, stats| {
                hello_pass(ring, &flow_tracker, &lineage, &parse, reject, outbox, stats)
            },
        ))
    })
    .context("starting the tls_hello pump's thread")
}

/// The loop of a pump whose passes a record's attribution waits on (as the
/// DNS query pump's, lab PR 229): woken by its ring, by a waiter asking for
/// a pass ([`DnsIngest::wanted`]) or by the stop check; each pass marked
/// with the time it began once it ran the ring empty; its events sent in
/// batches.
async fn ingest_pump(
    rb: RingBuf<MapData>,
    ingest: &DnsIngest,
    tx: BusSender,
    stop: &std::sync::atomic::AtomicBool,
    label: &'static str,
    size: usize,
    mut pass: impl FnMut(
        &mut RingBuf<MapData>,
        &mut RejectThrottle,
        &mut VecDeque<Event>,
        &mut PassStats,
    ) -> u32,
) -> std::io::Result<()> {
    let mut async_fd = crate::async_fd::register(rb)?;
    let mut reject = RejectThrottle::new();
    let mut outbox: VecDeque<Event> = VecDeque::new();
    let mut stats = PassStats::default();
    let mut last_summary = std::time::Instant::now();
    let mut check_stop = tokio::time::interval(std::time::Duration::from_millis(POLL_MS as u64));
    loop {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        tokio::select! {
            r = async_fd.readable_mut() => {
                let mut guard = r?;
                let began = crate::net::dns_ingest::monotonic_ns();
                let drained = pass(guard.get_inner_mut(), &mut reject, &mut outbox, &mut stats);
                guard.clear_ready();
                ingest.pass_ended(began);
                if drained == 0 {
                    reject.flush_idle(label, size);
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            () = ingest.wanted() => {
                let began = crate::net::dns_ingest::monotonic_ns();
                pass(async_fd.get_mut(), &mut reject, &mut outbox, &mut stats);
                ingest.pass_ended(began);
            }
            _ = check_stop.tick() => {}
        }
        if last_summary.elapsed() >= SUMMARY_EVERY {
            if stats.records > 0 {
                info!(
                    source = label,
                    records = stats.records,
                    decoded = stats.decoded,
                    last = %nn_model::log_escape::Escaped(stats.last.as_deref().unwrap_or("")),
                    "network telemetry: records read since the last summary"
                );
            }
            stats = PassStats::default();
            last_summary = std::time::Instant::now();
        }
        while !outbox.is_empty() {
            let n = outbox.len().min(crate::sensors::bus::BATCH_MAX);
            if tx.send_batch(outbox.drain(..n).collect()).await.is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_variant_per_parameter_count() {
        assert_eq!(
            variant_for("inet_csk_accept", 4),
            Some("inbound_accept_ret4")
        );
        assert_eq!(
            variant_for("inet_csk_accept", 2),
            Some("inbound_accept_ret2")
        );
        assert_eq!(variant_for("udp_recvmsg", 6), Some("dns_answer_v4_ret6"));
        assert_eq!(variant_for("udp_recvmsg", 5), Some("dns_answer_v4_ret5"));
        assert_eq!(variant_for("udpv6_recvmsg", 5), Some("dns_answer_v6_ret5"));
        assert_eq!(variant_for("udp_recvmsg", 3), None);
        assert_eq!(variant_for("tcp_sendmsg", 3), None);
        assert_eq!(other_arity("dns_answer_v4_ret6", Some(6)), None);
        assert!(other_arity("dns_answer_v4_ret6", Some(5))
            .unwrap()
            .contains("has 5"));
        assert!(other_arity("inbound_accept_ret2", None)
            .unwrap()
            .contains("no inet_csk_accept"));
        assert_eq!(other_arity("tcp_close", Some(2)), None, "not a variant");
        // the variants are the eBPF object's programs, each with the slot of
        // its return value after its parameters
        let dir = std::path::Path::new(concat!(env!("NN_REPO_ROOT"), "/agent-ebpf/src"));
        let src = std::fs::read_to_string(dir.join("inbound.rs")).unwrap()
            + &std::fs::read_to_string(dir.join("dns_answer.rs")).unwrap();
        for (p, _, n) in ARITY_VARIANTS {
            let at = src
                .find(&format!("pub fn {p}(ctx: FExitContext)"))
                .unwrap_or_else(|| panic!("{p}"));
            assert!(src[at..].starts_with(&format!("pub fn {p}(ctx: FExitContext)")));
            let body = &src[at..at + 200];
            assert!(body.contains(&format!("ctx.arg({n})")), "{p}: {body}");
        }
    }

    fn answer_raw() -> DnsAnswerRaw {
        let mut r = DnsAnswerRaw::zeroed();
        r.timestamp_ns = 5;
        r.pid = 42;
        r.uid = 1000;
        r.family = 2;
        r.server[..4].copy_from_slice(&[127, 0, 0, 53]);
        r.server_port = 53;
        r.datagram_len = 90;
        r.comm[..4].copy_from_slice(b"curl");
        r
    }

    #[test]
    fn a_decoded_response_gives_its_event_and_the_table_s_records() {
        let d = DnsAnswersOut {
            qname: "www.example".into(),
            qtype: 1,
            rcode: 0,
            records: vec![
                DnsRecordOut::Cname {
                    name: "www.example".into(),
                    ttl: 300,
                    target: "edge.example".into(),
                },
                DnsRecordOut::A {
                    name: "edge.example".into(),
                    ttl: 50,
                    addr: [198, 51, 100, 7],
                },
                DnsRecordOut::Aaaa {
                    name: "edge.example".into(),
                    ttl: 40,
                    addr: "::ffff:198.51.100.8"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                },
                DnsRecordOut::A {
                    name: "edge.example".into(),
                    ttl: 20,
                    addr: [198, 51, 100, 9],
                },
            ],
            complete: true,
        };
        let (ev, recs) = answer_event(&answer_raw(), Some(&d), Some("/usr/bin/curl".into()));
        assert_eq!(ev.query_name.as_deref(), Some("www.example"));
        assert_eq!(ev.server.to_string(), "127.0.0.53");
        assert_eq!(ev.addrs.len(), 3);
        assert_eq!(
            ev.addrs[1].to_string(),
            "198.51.100.8",
            "the mapped form folded"
        );
        assert_eq!(ev.cnames, vec!["edge.example".to_string()]);
        assert_eq!(ev.ttl_secs, 20);
        assert!(!ev.truncated);
        assert_eq!(recs.len(), 4);
        // not decoded: no name, nothing for the table; a cut message: truncated
        let mut raw = answer_raw();
        raw.flags = answer_flags::TRUNCATED;
        let (ev, recs) = answer_event(&raw, None, None);
        assert!(ev.query_name.is_none() && recs.is_empty() && ev.truncated);
        let incomplete = DnsAnswersOut {
            complete: false,
            ..d
        };
        assert!(
            answer_event(&answer_raw(), Some(&incomplete), None)
                .0
                .truncated
        );
    }

    #[test]
    fn a_hello_s_outcomes() {
        let mut raw = TlsHelloRaw::zeroed();
        raw.family = 2;
        raw.dst_addr[..4].copy_from_slice(&[198, 51, 100, 7]);
        raw.dst_port = 443;
        raw.flow_id[..8].copy_from_slice(&77u64.to_le_bytes());
        raw.flags = tls_flags::TRUNCATED;
        let done = TlsOut::Complete {
            ja3: "a".repeat(32),
            ja4: "t13d1516h2_8daaf6152771_02713d6af862".into(),
            sni: SniOut::Host("example.com".into()),
            alpn: vec!["h2".into()],
        };
        let ev = hello_event(&raw, Some(&done), None);
        assert_eq!(ev.outcome, TlsHelloOutcome::Complete);
        let fp = ev.fingerprint.unwrap();
        assert_eq!((fp.sni.as_deref(), fp.alpn.len()), (Some("example.com"), 1));
        assert_eq!(ev.flow_start_ns, 77);
        assert!(ev.truncated);
        assert_eq!(ev.dst_addr.to_string(), "198.51.100.7");
        for (out, want) in [
            (Some(TlsOut::Incomplete), TlsHelloOutcome::Incomplete),
            (Some(TlsOut::Invalid), TlsHelloOutcome::Invalid),
            (None, TlsHelloOutcome::Undecoded),
        ] {
            let ev = hello_event(&raw, out.as_ref(), None);
            assert_eq!(ev.outcome, want);
            assert!(ev.fingerprint.is_none());
        }
        let nc = TlsOut::Complete {
            ja3: "b".repeat(32),
            ja4: "t13d1516h2_8daaf6152771_02713d6af862".into(),
            sni: SniOut::NonConforming,
            alpn: vec![],
        };
        assert_eq!(
            hello_event(&raw, Some(&nc), None).fingerprint.unwrap().sni,
            None
        );
    }

    /// A response the worker decoded binds its receiver; one it could not
    /// decode makes the unbound unknown; held records are noted; bytes that
    /// are no response are no evidence.
    #[test]
    fn a_response_record_feeds_the_table() {
        use nn_model::telemetry::DnsResolution;
        const S: u64 = 1_000_000_000;
        let c2: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let out = DnsAnswersOut {
            qname: "c2.example".into(),
            qtype: 1,
            rcode: 0,
            records: vec![DnsRecordOut::A {
                name: "c2.example".into(),
                ttl: 60,
                addr: [203, 0, 113, 5],
            }],
            complete: true,
        };
        let t = ResolvedTable::default();
        let mut stats = PassStats::default();
        let mut raw = answer_raw();
        raw.timestamp_ns = 10 * S;
        let evs = ingest_answer(&raw, Some(Some(out.clone())), None, &t, &mut stats);
        assert!(matches!(evs.as_slice(), [Event::DnsAnswer(_)]));
        assert_eq!(t.check(42, 1, c2, 11 * S, Vec::new), DnsResolution::Lineage);
        assert_eq!((stats.records, stats.decoded), (1, 1));
        assert!(stats
            .last
            .as_deref()
            .unwrap()
            .starts_with("c2.example -> 1"));
        // no DNS response: nothing changes
        let t = ResolvedTable::default();
        ingest_answer(&raw, Some(None), None, &t, &mut stats);
        assert_eq!(
            t.check(7, 1, c2, 11 * S, Vec::new),
            DnsResolution::Unresolved
        );
        // the worker did not answer: unknown for a while
        ingest_answer(&raw, None, None, &t, &mut stats);
        assert_eq!(t.check(7, 1, c2, 11 * S, Vec::new), DnsResolution::Unknown);
        // held records of the receiver: its connects unknown
        let t = ResolvedTable::default();
        let mut held = answer_raw();
        held.timestamp_ns = 10 * S;
        held.flags = held_flags::TASK;
        held.held = 3;
        let evs = ingest_answer(&held, Some(None), None, &t, &mut stats);
        assert_eq!(evs.len(), 2, "the event and its flood");
        assert_eq!(t.check(42, 1, c2, 11 * S, Vec::new), DnsResolution::Unknown);
        assert_eq!(
            t.check(43, 1, c2, 11 * S, Vec::new),
            DnsResolution::Unresolved
        );
    }

    fn one_a(name: &str, addr: [u8; 4], complete: bool) -> DnsAnswersOut {
        DnsAnswersOut {
            qname: name.into(),
            qtype: 1,
            rcode: 0,
            records: vec![DnsRecordOut::A {
                name: name.into(),
                ttl: 60,
                addr,
            }],
            complete,
        }
    }

    /// Review of #495, D1 (the reviewer's probe P1b, which passed on the
    /// PR's first head): a response the sensor cut (TRUNCATED) or the worker
    /// read incomplete binds what it read and answers nothing — the address
    /// past the cut is unknown, never unresolved.
    #[test]
    fn a_cut_response_answers_nothing() {
        use nn_model::telemetry::DnsResolution;
        const S: u64 = 1_000_000_000;
        let a1: std::net::IpAddr = "198.51.100.1".parse().unwrap();
        let a2: std::net::IpAddr = "198.51.100.2".parse().unwrap();
        for (flags, complete) in [(answer_flags::TRUNCATED, true), (0, false)] {
            let t = ResolvedTable::default();
            t.on_query(42, "big.example", 10 * S - 1);
            assert_eq!(t.check(42, 1, a2, 11 * S, Vec::new), DnsResolution::Unknown);
            let mut stats = PassStats::default();
            let mut raw = answer_raw();
            raw.timestamp_ns = 10 * S;
            raw.flags = flags;
            let evs = ingest_answer(
                &raw,
                Some(Some(one_a("big.example", [198, 51, 100, 1], complete))),
                None,
                &t,
                &mut stats,
            );
            match &evs[0] {
                Event::DnsAnswer(e) => assert!(e.truncated),
                _ => panic!(),
            }
            assert_eq!(t.check(42, 1, a1, 11 * S, Vec::new), DnsResolution::Lineage);
            assert_eq!(
                t.check(42, 1, a2, 11 * S, Vec::new),
                DnsResolution::Unknown,
                "flags {flags} complete {complete}"
            );
        }
        // a datagram from port 53 whose bytes were not read: its receiver's
        // evidence incomplete
        let t = ResolvedTable::default();
        let mut raw = answer_raw();
        raw.timestamp_ns = 10 * S;
        raw.flags = answer_flags::UNREAD;
        ingest_answer(&raw, Some(None), None, &t, &mut PassStats::default());
        assert_eq!(t.check(42, 1, a2, 11 * S, Vec::new), DnsResolution::Unknown);
        assert_eq!(
            t.check(43, 1, a2, 11 * S, Vec::new),
            DnsResolution::Unresolved
        );
    }

    /// Review of #495, D3: a user's held responses (the count rides on the
    /// user's next record, whichever process it is) leave every process's
    /// evidence incomplete — not the reporter's alone.
    #[test]
    fn a_user_s_held_responses_degrade_every_process() {
        use nn_model::telemetry::DnsResolution;
        const S: u64 = 1_000_000_000;
        let c2: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let t = ResolvedTable::default();
        let mut raw = answer_raw();
        raw.timestamp_ns = 10 * S;
        raw.flags = held_flags::UID;
        raw.held_uid = 9;
        ingest_answer(&raw, Some(None), None, &t, &mut PassStats::default());
        for pid in [42, 43, 4242] {
            assert_eq!(
                t.check(pid, 1, c2, 11 * S, Vec::new),
                DnsResolution::Unknown
            );
        }
    }

    /// Review of #495, D4: a response any process received binds that
    /// process only; one a system resolver received (its executable and a
    /// system uid) binds the processes that asked its name, and the name
    /// counts host-wide.
    #[test]
    fn only_a_system_resolver_s_response_binds_others() {
        use nn_model::telemetry::DnsResolution;
        const S: u64 = 1_000_000_000;
        let c2: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let resolved_exe = Some("/usr/lib/systemd/systemd-resolved".to_string());
        for (exe, uid, bound) in [
            (None, 1000, false),
            (Some("/usr/bin/python3".to_string()), 1000, false),
            // a user's copy of the resolver's program
            (resolved_exe.clone(), 1000, false),
            (resolved_exe.clone(), 101, true),
        ] {
            let t = ResolvedTable::default();
            t.on_query(777, "c2.example", 10 * S - 1);
            let mut raw = answer_raw();
            raw.timestamp_ns = 10 * S;
            raw.uid = uid;
            raw.pid = 500;
            ingest_answer(
                &raw,
                Some(Some(one_a("c2.example", [203, 0, 113, 5], true))),
                exe.clone(),
                &t,
                &mut PassStats::default(),
            );
            assert_eq!(
                t.check(500, 1, c2, 11 * S, Vec::new),
                DnsResolution::Lineage
            );
            let want = if bound {
                DnsResolution::Lineage
            } else {
                DnsResolution::Unknown
            };
            assert_eq!(t.check(777, 1, c2, 11 * S, Vec::new), want, "{exe:?} {uid}");
            let other = if bound {
                DnsResolution::OtherLineage
            } else {
                DnsResolution::Unresolved
            };
            assert_eq!(
                t.check(888, 1, c2, 11 * S, Vec::new),
                other,
                "{exe:?} {uid}"
            );
        }
    }

    /// Review of #495, D2: 1,024 responses a second for one user (its
    /// sustained budget) outrun a pump that decodes about one a millisecond.
    /// A connect whose barrier the pump had not reached is judged unknown,
    /// never unresolved for want of the responses still in the ring; once
    /// the pump has read them, it is bound.
    #[test]
    fn a_connect_ahead_of_the_response_pump_is_unknown() {
        use nn_model::telemetry::DnsResolution;
        const MS: u64 = 1_000_000;
        let now = crate::net::dns_ingest::monotonic_ns();
        let t = Arc::new(ResolvedTable::default());
        let _claim = crate::net::resolved::ResolvedClaim::new(Arc::clone(&t), 1);
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // the second's responses, 1,024 of them; the process that connects
        // asked the last name; the pump has read the first 1,000 only
        let base = now - 1_300 * MS;
        let ts = |i: u64| base + i * 1_000 * MS / 1024;
        t.on_query(777, "n1023.example", ts(1023) - 1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut stats = PassStats::default();
        for i in 0..1024u64 {
            if i == 1000 {
                t.ingest().pass_ended(ts(999));
            }
            if i >= 1000 {
                continue;
            }
            let mut raw = answer_raw();
            raw.timestamp_ns = ts(i);
            raw.pid = 4000 + (i % 7) as u32;
            let name = format!("n{i}.example");
            ingest_answer(
                &raw,
                Some(Some(one_a(&name, [203, 0, 113, (i % 250) as u8], true))),
                None,
                &t,
                &mut stats,
            );
        }
        let c2: std::net::IpAddr = "203.0.113.23".parse().unwrap();
        // the connect, 1 ms after the last response, now over 250 ms ago
        let connect = ts(1023) + MS;
        let caught = rt.block_on(t.ingest().caught_up(connect));
        assert!(!caught, "the pump is behind");
        let got = crate::net::resolved::judge(&t, &lineage, 777, 1, c2, connect, caught);
        assert_eq!(got, DnsResolution::Unknown);
        // the pump reads the rest — its answer bound to the asker? not a
        // resolver's: the asker's own response binds it
        let mut raw = answer_raw();
        raw.timestamp_ns = ts(1023);
        raw.pid = 777;
        ingest_answer(
            &raw,
            Some(Some(one_a("n1023.example", [203, 0, 113, 23], true))),
            None,
            &t,
            &mut stats,
        );
        t.ingest().pass_ended(connect + MS);
        let caught = rt.block_on(t.ingest().caught_up(connect));
        assert!(caught);
        assert_eq!(
            crate::net::resolved::judge(&t, &lineage, 777, 1, c2, connect, caught),
            DnsResolution::Lineage
        );
    }

    /// Review of #495, RA5: only the bytes the sensor copied are decoded.
    #[test]
    fn only_the_captured_bytes_are_decoded() {
        let mut raw = answer_raw();
        raw.payload[..4].copy_from_slice(&[1, 2, 3, 4]);
        raw.payload[4] = 9;
        raw.captured = 4;
        assert_eq!(captured_payload(&raw), &[1, 2, 3, 4]);
        raw.captured = 0;
        assert!(captured_payload(&raw).is_empty());
        raw.captured = u16::MAX;
        assert_eq!(captured_payload(&raw).len(), raw.payload.len());
    }

    /// A hello's fingerprint goes to its pending flow (a flow with no
    /// correlator, a connect the agent did not see, has none to take it).
    #[test]
    fn a_hello_record_s_fingerprint_joins_its_flow() {
        let tracker = Mutex::new(FlowTracker::default());
        let info = crate::net::flow_tracker::TcpConnectInfo {
            start_ns: 77,
            sk_ptr: 0xabc,
            family: 2,
            src_addr: "0.0.0.0".parse().unwrap(),
            src_port: 0,
            dst_addr: "198.51.100.7".parse().unwrap(),
            dst_port: 443,
            proto: 6,
            pid: 42,
            uid: 1000,
            comm: "curl".into(),
            exe: None,
            proc_start_ns: 1,
        };
        tracker.lock().on_tcp_connect(&info);
        let mut raw = TlsHelloRaw::zeroed();
        raw.flow_id = FlowTracker::corr_id(77, 0xabc);
        let done = TlsOut::Complete {
            ja3: "a".repeat(32),
            ja4: "t13d1516h2_8daaf6152771_02713d6af862".into(),
            sni: SniOut::Host("example.com".into()),
            alpn: vec![],
        };
        let mut stats = PassStats::default();
        let evs = ingest_hello(&raw, Some(&done), None, &tracker, &mut stats);
        assert_eq!(evs.len(), 1);
        assert_eq!((stats.records, stats.decoded), (1, 1));
        let snap = tracker.lock().due_snapshots(
            100,
            &crate::net::flow_tracker::SnapshotPolicy {
                interval_ns: 1,
                min_age_ns: 1,
                max_per_tick: 4,
            },
        );
        assert_eq!(
            snap.flows[0]
                .tls_fingerprint
                .as_ref()
                .and_then(|f| f.sni.as_deref()),
            Some("example.com")
        );
        // an incomplete hello: nothing attached, counted undecoded
        let mut s2 = PassStats::default();
        ingest_hello(&raw, Some(&TlsOut::Incomplete), None, &tracker, &mut s2);
        assert_eq!((s2.records, s2.decoded), (1, 0));
    }

    #[test]
    fn held_counts_count_only_with_their_flags() {
        let got: Vec<Event> =
            floods(FloodSource::TlsHello, held_flags::UID, (5, 6), 1, 2, "x", 3).collect();
        assert_eq!(got.len(), 1);
        assert!(matches!(
            &got[0],
            Event::SensorFlood {
                held: 6,
                uid_level: true,
                source: FloodSource::TlsHello,
                ..
            }
        ));
        assert_eq!(
            floods(FloodSource::DnsAnswer, 0, (5, 6), 1, 2, "x", 3).count(),
            0
        );
    }
}
