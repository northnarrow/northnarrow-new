//! The core's export thread (lot 276): `nn-export`, never the decision
//! thread, never a lock of the evidence writers'.
//!
//! For each sink and each configured chain: read the rows after the
//! sink's place (`nn_export::wal`, the core reading its own files, the
//! rows verbatim), hand them to the export worker, apply its answer — the
//! last row delivered moves the cursor, the last row committed is where
//! the next request starts. An answer that names a row the core never sent
//! the worker is a lie: the worker is killed (`Workers::condemn`). The
//! rows the export can no longer deliver are stage 8, counted and signed.
//!
//! What the worker costs the agent is this thread's reads and its waits on
//! the worker (each request bounded by its budget): the decision, the bus
//! and the evidence writers never wait on the export.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use nn_export::config::{ExportConfig, Start};
use nn_export::wal::{self, Cursor, Cursors, Note, Source};
use nn_linux::chain_host_linux::LinuxHost;
use nn_linux::worker::{Health, WorkerError, Workers};
use nn_proto::admin_protocol::{ExportChainStatus, ExportSinkStatus};
use nn_proto::ipc::{
    Answer, ExportAddr, ExportChain, ExportRow, ExportRows, ExportRowsOut, ExportSetup, ExportSink,
    FileSetup, Request, RowPos, SinkFault, SinkState, SyslogSetup, WorkerKind, MAX_EXPORT_BYTES,
    MAX_EXPORT_ROWS, MAX_RECORDS_PER_ROW,
};
use parking_lot::Mutex;
use tracing::{info, warn};

use super::{Configured, ExportHandle};
use crate::audit::{AuditEntryDraft, AuditLog};

/// The audit op of the export's signed rows.
pub const EXPORT_OP: &str = "export_state";

/// The thread's name.
pub const THREAD: &str = "nn-export";

/// Rows sent and not delivered, per sink and chain: beyond them the core
/// reads no more, and asks for acknowledgements only.
pub const MAX_WINDOW: usize = 4096;

/// What the worker may spend on one request, and what the core waits
/// beyond it before the worker counts as hung.
pub const BUDGET: Duration = Duration::from_millis(1000);
pub const MARGIN: Duration = Duration::from_millis(2000);

/// The pause of a round that moved nothing, and of a worker not ready.
pub const IDLE: Duration = Duration::from_millis(200);

/// Cursors written at most this often (and at the stop).
pub const SAVE_EVERY: Duration = Duration::from_secs(2);

/// A better state's row waits for this; a worse one is signed at once.
pub const STATE_ROW_EVERY: Duration = Duration::from_secs(60);

/// The fault in words (the status, the signed rows).
pub fn fault_text(f: &SinkFault) -> String {
    match f {
        SinkFault::NotSetUp => "the worker has had no setup".into(),
        SinkFault::Connect(e) => format!("connect: {}", std::io::Error::from_raw_os_error(*e)),
        SinkFault::ConnectTimeout => "no TCP connection in time".into(),
        SinkFault::HandshakeTimeout => "no TLS session in time".into(),
        SinkFault::Tls(t) => format!("TLS: {t:?}").to_lowercase(),
        SinkFault::Closed => "the receiver closed the connection".into(),
        SinkFault::Io(e) => format!("I/O: {}", std::io::Error::from_raw_os_error(*e)),
        SinkFault::PeerData => "the receiver sent data".into(),
        SinkFault::BadTrust => "the CA bundle or the server name is not usable".into(),
        SinkFault::File(e) => format!("file: {}", std::io::Error::from_raw_os_error(*e)),
        SinkFault::Pin => "the connects could not be pinned to the receiver's port".into(),
    }
}

/// What the thread is given.
pub struct Params {
    pub configured: Configured,
    pub workers: Workers,
    pub chains: crate::chains::ChainPaths,
    pub pubkey: VerifyingKey,
    pub agent_id: [u8; 16],
    pub audit: Option<Arc<Mutex<AuditLog>>>,
    pub cursors: PathBuf,
    pub handle: ExportHandle,
}

/// The running thread.
pub struct Running {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    /// Stop it: its cursors written, its stop row signed; waited for at
    /// most a request's budget and margin.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let until = Instant::now() + BUDGET + MARGIN + Duration::from_secs(1);
            while !j.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            if j.is_finished() {
                let _ = j.join();
            }
        }
    }
}

/// Start the thread.
pub fn start(p: Params) -> std::io::Result<Running> {
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    // running from before the thread (which says it ended when it does)
    let handle = p.handle.clone();
    handle.set_running(true);
    let join = std::thread::Builder::new()
        .name(THREAD.into())
        .spawn(move || {
            // R14c: the export's thread holds no capability
            nn_linux::caps::enter_or_report(nn_linux::caps::Role::Export);
            // however it ends (a stop, a panic), the export says it no
            // longer runs (the review of #499, D4)
            struct Ended(super::ExportHandle);
            impl Drop for Ended {
                fn drop(&mut self) {
                    self.0.set_running(false);
                }
            }
            let _ended = Ended(p.handle.clone());
            run(p, &s)
        })
        .inspect_err(|_| handle.set_running(false))?;
    Ok(Running {
        stop,
        join: Some(join),
    })
}

fn source(chain: ExportChain, paths: &crate::chains::ChainPaths) -> Source {
    let active = match chain {
        ExportChain::Detections => paths.detections.clone(),
        ExportChain::Actions => paths.actions.clone(),
        ExportChain::FimDrift => paths.fim_drift.clone(),
        ExportChain::Netflow => paths.netflow.clone(),
        ExportChain::CanaryAccess => paths.canary_access.clone(),
    };
    Source { chain, active }
}

/// A row sent and not delivered yet.
#[derive(Debug, Clone)]
struct Sent {
    pos: RowPos,
    end: u64,
    hash: String,
}

impl Sent {
    fn cursor(&self) -> Cursor {
        Cursor {
            file: self.pos.file,
            line: self.pos.line,
            end: self.end,
            hash: self.hash.clone(),
        }
    }
}

struct ChainRun {
    src: Source,
    cursor: Cursor,
    /// The cursor came from disk and has not been checked against the
    /// chain yet.
    unchecked: bool,
    window: VecDeque<Sent>,
    /// Where the next read starts.
    next: Cursor,
    lost: u64,
    dirty: bool,
}

struct SinkRun {
    sink: ExportSink,
    target: String,
    chains: Vec<ChainRun>,
    until: Option<Instant>,
    state: Option<SinkState>,
    fault: Option<SinkFault>,
    rows: u64,
    records: u64,
    unverified: u64,
    faults: u64,
    last_delivery: Option<String>,
    /// The last state signed, and when.
    signed: Option<(Option<SinkState>, Instant)>,
}

impl SinkRun {
    fn lost(&self) -> u64 {
        self.chains.iter().map(|c| c.lost).sum()
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// The host's name for RFC 5424 and OCSF's `device` (`-` if none fits).
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| nn_proto::ipc::hostname_ok(h))
        .unwrap_or_else(|| "-".to_string())
}

fn setup_of(p: &Params) -> ExportSetup {
    let c = &p.configured.config;
    ExportSetup {
        agent_id: hex::encode(p.agent_id),
        hostname: hostname(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pubkey: p.pubkey.to_bytes(),
        file: c.file.as_ref().map(|f| FileSetup {
            max_bytes: f.max_bytes,
            max_files: f.max_files,
        }),
        syslog: c.syslog.as_ref().map(|s| SyslogSetup {
            addr: match s.addr.ip() {
                std::net::IpAddr::V4(a) => ExportAddr::V4(a.octets()),
                std::net::IpAddr::V6(a) => ExportAddr::V6(a.octets()),
            },
            port: s.addr.port(),
            server_name: s.server_name.clone(),
            ca_pem: p.configured.ca_pem.clone().unwrap_or_default(),
            facility: s.facility,
            // the kernel's Landlock handles TCP (ABI 4): the pin is asked
            // for, and an answer without it refused
            pin_port: nn_linux::sandbox::kernel_landlock_abi() >= 4,
        }),
    }
}

fn sinks_of(c: &ExportConfig) -> Vec<(ExportSink, String)> {
    let mut v = Vec::new();
    if c.file.is_some() {
        v.push((ExportSink::File, nn_proto::ipc::EXPORT_DIR.to_string()));
    }
    if let Some(s) = &c.syslog {
        v.push((
            ExportSink::Syslog,
            format!("{} ({})", s.addr, s.server_name),
        ));
    }
    v
}

fn sign(audit: &Option<Arc<Mutex<AuditLog>>>, result: &str, extra: serde_json::Value) {
    let Some(log) = audit else {
        return;
    };
    let draft = AuditEntryDraft {
        op: EXPORT_OP.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "an export_state row was not written");
    }
}

fn cursors_json(sinks: &[SinkRun]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for k in sinks {
        for c in &k.chains {
            m.insert(
                wal::key(k.sink, c.src.chain),
                serde_json::json!([c.cursor.file, c.cursor.line]),
            );
        }
    }
    serde_json::Value::Object(m)
}

fn note_json(n: &Note) -> serde_json::Value {
    match n {
        Note::Evicted { files, rows } => {
            serde_json::json!({"note": "evicted", "files": files, "rows": rows})
        }
        Note::CursorGone { file, line } => {
            serde_json::json!({"note": "cursor_gone", "file": file, "line": line})
        }
        Note::CursorAhead { file } => serde_json::json!({"note": "cursor_ahead", "file": file}),
        Note::Oversize { file, line, bytes } => {
            serde_json::json!({"note": "oversize", "file": file, "line": line, "bytes": bytes})
        }
        Note::Blank { file, line } => {
            serde_json::json!({"note": "blank", "file": file, "line": line})
        }
    }
}

/// The chain's bytes after `c` (how far a sink is behind).
fn behind(src: &Source, c: &Cursor) -> u64 {
    let size = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    if !src.chain.rotates() {
        return size(&src.active).saturating_sub(c.end);
    }
    let current = wal::current_file(src);
    let mut total = 0u64;
    for f in c.file..=current {
        let p = if f == current {
            src.active.clone()
        } else {
            nn_evidence::chainlog::archive_path_for(&src.active, f)
        };
        let s = size(&p);
        total += if f == c.file {
            s.saturating_sub(c.end)
        } else {
            s
        };
    }
    total
}

fn state_rank(s: Option<SinkState>) -> u8 {
    match s {
        Some(SinkState::Up) => 0,
        None | Some(SinkState::Off) => 1,
        Some(SinkState::Connecting) => 2,
        Some(SinkState::Down) => 3,
        Some(SinkState::Failed) => 4,
    }
}

fn run(p: Params, stop: &AtomicBool) {
    // the export yields to the agent's own work
    // SAFETY: setpriority on this thread's id.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 10);
    }
    let cfg = p.configured.config.clone();
    let (mut saved, why) = Cursors::load(&p.cursors);
    if let Some(why) = &why {
        warn!(path = %p.cursors.display(), %why, "the export's cursors do not read: the sinks start as configured");
    }
    let mut sinks: Vec<SinkRun> = sinks_of(&cfg)
        .into_iter()
        .map(|(sink, target)| SinkRun {
            sink,
            target,
            chains: cfg
                .chains
                .iter()
                .map(|&chain| {
                    let src = source(chain, &p.chains);
                    let (cursor, unchecked) = match saved.cursors.get(&wal::key(sink, chain)) {
                        Some(c) => (c.clone(), true),
                        None => (
                            wal::initial::<LinuxHost>(&src, cfg.start == Start::Oldest)
                                .unwrap_or_else(|_| Cursor::start_of(wal::current_file(&src))),
                            false,
                        ),
                    };
                    ChainRun {
                        next: cursor.clone(),
                        src,
                        cursor,
                        unchecked,
                        window: VecDeque::new(),
                        lost: 0,
                        dirty: true,
                    }
                })
                .collect(),
            until: None,
            state: None,
            fault: None,
            rows: 0,
            records: 0,
            unverified: 0,
            faults: 0,
            last_delivery: None,
            signed: None,
        })
        .collect();
    let setup = setup_of(&p);
    info!(config = %cfg.summary(), "export: on");
    sign(
        &p.audit,
        "success",
        serde_json::json!({
            "at": "start",
            "config_sha256": p.configured.sha256,
            "ocsf_version": nn_export::OCSF_VERSION,
            "chains": cfg.chains.iter().map(|c| c.name()).collect::<Vec<_>>(),
            "sinks": sinks.iter().map(|k| format!("{} {}", k.sink.name(), k.target)).collect::<Vec<_>>(),
            "cursors": cursors_json(&sinks),
            "cursors_file": why.map(|w| format!("not read: {w}")),
        }),
    );
    let mut set_up_for: Option<u64> = None;
    let mut setup_warned: Option<Instant> = None;
    let mut port_pinned = None;
    let mut last_save = Instant::now() - SAVE_EVERY;
    let mut saved_at: Option<String> = None;
    let mut saves = 0u64;
    let dir_limits = p
        .configured
        .config
        .file
        .as_ref()
        .map(|f| (f.max_files, nn_export::config::dir_bound(f)));
    let mut dir_checked = Instant::now() - DIR_CHECK_EVERY;
    let mut dir_over: Option<String> = None;
    while !stop.load(Ordering::SeqCst) {
        // the file sink's directory within its bound, or the file sink
        // stops and the worker that wrote past it is killed
        if let Some((max_files, bound)) = dir_limits {
            if dir_checked.elapsed() >= DIR_CHECK_EVERY {
                dir_checked = Instant::now();
                let now_over = over_bound(
                    std::path::Path::new(nn_proto::ipc::EXPORT_DIR),
                    max_files,
                    bound,
                );
                if let (Some(why), None) = (&now_over, &dir_over) {
                    warn!(%why, "export: the export's directory past its bound: the worker killed, the file sink stopped");
                    p.workers
                        .condemn(WorkerKind::Export, "export: its directory past its bound");
                    sign(
                        &p.audit,
                        "detected",
                        serde_json::json!({"at": "note", "note": "directory_over", "sink": "file", "why": why}),
                    );
                }
                dir_over = now_over;
            }
            if dir_over.is_some() {
                for k in sinks.iter_mut().filter(|k| k.sink == ExportSink::File) {
                    k.until = Some(Instant::now() + DIR_CHECK_EVERY);
                    k.state = Some(SinkState::Failed);
                    k.fault = Some(SinkFault::File(libc::EFBIG));
                }
            }
        }
        let status = p
            .workers
            .status()
            .into_iter()
            .find(|w| w.kind == WorkerKind::Export);
        let worker = status
            .as_ref()
            .map_or("unavailable".to_string(), |w| w.health.as_str().to_string());
        let mut busy = false;
        match status {
            Some(w) if w.health == Health::Ready => {
                if set_up_for != Some(w.starts) {
                    let answer = p.workers.request(
                        WorkerKind::Export,
                        &Request::ExportSetup(setup.clone()),
                        BUDGET + MARGIN,
                    );
                    if let Ok(Answer::ExportSetup(out)) = answer {
                        set_up_for = Some(w.starts);
                        port_pinned = setup.syslog.as_ref().map(|_| out.port_pinned);
                        for k in &mut sinks {
                            k.until = None;
                            k.state = Some(match k.sink {
                                ExportSink::File => out.file,
                                ExportSink::Syslog => out.syslog,
                            });
                            for c in &mut k.chains {
                                c.window.clear();
                                c.next = c.cursor.clone();
                            }
                        }
                        info!(
                            worker_starts = w.starts,
                            ?port_pinned,
                            "export: worker set up"
                        );
                    } else if setup_warned.is_none_or(|t: Instant| t.elapsed() >= STATE_ROW_EVERY) {
                        // the supervisor kills and reports a worker that
                        // breaks the protocol; this says why nothing moves
                        warn!(answer = ?answer.err(), "export: the worker took no setup");
                        setup_warned = Some(Instant::now());
                    }
                }
                if set_up_for == Some(w.starts) {
                    for k in &mut sinks {
                        if k.until.is_some_and(|t| t > Instant::now()) {
                            continue;
                        }
                        k.until = None;
                        for i in 0..k.chains.len() {
                            busy |= round(&p, k, i, &mut set_up_for);
                            if set_up_for.is_none() {
                                break;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        // stage 8 and the published state
        let total_lost: u64 = sinks.iter().map(SinkRun::lost).sum();
        let before = p.handle.lost().unwrap_or(0);
        if total_lost > before {
            p.handle.add_lost(total_lost - before);
        }
        if sinks.iter().flat_map(|k| &k.chains).any(|c| c.dirty)
            && last_save.elapsed() >= SAVE_EVERY
        {
            save(&p, &mut sinks, &mut saved);
            last_save = Instant::now();
            saved_at = Some(now_rfc3339());
            saves += 1;
        }
        sign_changes(&p, &mut sinks);
        p.handle.publish(
            worker,
            port_pinned,
            sinks.iter().map(sink_status).collect(),
            saved_at.clone(),
            saves,
        );
        if !busy {
            std::thread::sleep(IDLE);
        }
    }
    save(&p, &mut sinks, &mut saved);
    sign(
        &p.audit,
        "success",
        serde_json::json!({
            "at": "stop",
            "sinks": sinks.iter().map(|k| serde_json::json!({
                "sink": k.sink.name(),
                "rows": k.rows,
                "records": k.records,
                "unverified": k.unverified,
                "faults": k.faults,
                "lost": k.lost(),
            })).collect::<Vec<_>>(),
            "cursors": cursors_json(&sinks),
        }),
    );
    info!("export: stopped, cursors written");
}

fn save(p: &Params, sinks: &mut [SinkRun], saved: &mut Cursors) {
    for k in sinks.iter_mut() {
        for c in &mut k.chains {
            saved
                .cursors
                .insert(wal::key(k.sink, c.src.chain), c.cursor.clone());
            c.dirty = false;
        }
    }
    if let Err(e) = saved.save(&p.cursors) {
        warn!(path = %p.cursors.display(), error = %e, "the export's cursors were not written");
    }
}

fn sink_status(k: &SinkRun) -> ExportSinkStatus {
    ExportSinkStatus {
        sink: k.sink.name().to_string(),
        target: k.target.clone(),
        state: k.state.map_or("waiting", SinkState::name).to_string(),
        fault: k.fault.as_ref().map(fault_text),
        rows: k.rows,
        records: k.records,
        unverified: k.unverified,
        faults: k.faults,
        lost: k.lost(),
        last_delivery: k.last_delivery.clone(),
        chains: k
            .chains
            .iter()
            .map(|c| ExportChainStatus {
                chain: c.src.chain.name().to_string(),
                cursor: (c.cursor.line > 0).then_some((c.cursor.file, c.cursor.line)),
                in_flight: c.window.len() as u64,
                behind_bytes: behind(&c.src, &c.cursor),
                lost: c.lost,
            })
            .collect(),
    }
}

/// A sink's state change signed: a worse one at once, a better one at most
/// once a minute.
fn sign_changes(p: &Params, sinks: &mut [SinkRun]) {
    for k in sinks.iter_mut() {
        let due = match k.signed {
            None => k.state.is_some(),
            Some((s, _)) if s == k.state => false,
            Some((s, at)) => state_rank(k.state) > state_rank(s) || at.elapsed() >= STATE_ROW_EVERY,
        };
        if !due {
            continue;
        }
        let worse = k
            .signed
            .is_some_and(|(s, _)| state_rank(k.state) > state_rank(s));
        sign(
            &p.audit,
            if worse { "detected" } else { "success" },
            serde_json::json!({
                "at": "sink",
                "sink": k.sink.name(),
                "target": k.target,
                "from": k.signed.and_then(|(s, _)| s).map(SinkState::name),
                "to": k.state.map(SinkState::name),
                "fault": k.fault.as_ref().map(fault_text),
                "rows": k.rows,
                "records": k.records,
                "unverified": k.unverified,
                "lost": k.lost(),
            }),
        );
        if worse {
            warn!(sink = k.sink.name(), state = ?k.state, fault = ?k.fault, "export: a sink is not delivering");
        }
        k.signed = Some((k.state, Instant::now()));
    }
}

/// What an answer did to a chain's place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Applied {
    /// Rows delivered by it: the cursor moved past them.
    delivered: usize,
}

/// Apply a worker's answer to the chain's place: `sent`, the rows of the
/// request it answers, join the window; the rows up to the one acked leave
/// it and move the cursor; the next read starts after the one committed
/// (from the cursor when that is none or behind it). `Err`: the answer
/// names a row the core never gave this worker, or more records than the
/// rows it delivers can give — a lie, the worker is killed.
fn apply(c: &mut ChainRun, sent: Vec<Sent>, out: &ExportRowsOut) -> Result<Applied, &'static str> {
    c.window.extend(sent);
    let known =
        |pos: RowPos, c: &ChainRun| pos <= c.cursor.pos() || c.window.iter().any(|s| s.pos == pos);
    if out.acked.is_some_and(|a| !known(a, c)) || out.committed.is_some_and(|x| !known(x, c)) {
        c.window.clear();
        c.next = c.cursor.clone();
        return Err("export_rows: a row the core did not send");
    }
    let delivered = out
        .acked
        .map_or(0, |a| c.window.iter().filter(|s| s.pos <= a).count());
    if u64::from(out.records) > delivered as u64 * u64::from(MAX_RECORDS_PER_ROW) {
        c.window.clear();
        c.next = c.cursor.clone();
        return Err("export_rows: more records than the rows delivered give");
    }
    if let Some(a) = out.acked {
        while c.window.front().is_some_and(|s| s.pos <= a) {
            if let Some(s) = c.window.pop_front() {
                c.cursor = s.cursor();
                c.dirty = true;
            }
        }
    }
    // the next request starts after the last row committed; rows after it
    // were not written, and are read again
    match out.committed {
        Some(x) if x > c.cursor.pos() => {
            while c.window.back().is_some_and(|s| s.pos > x) {
                c.window.pop_back();
            }
            c.next = c
                .window
                .back()
                .map_or_else(|| c.cursor.clone(), Sent::cursor);
        }
        _ => {
            c.window.clear();
            c.next = c.cursor.clone();
        }
    }
    Ok(Applied { delivered })
}

/// The rows of a batch a request can carry: each row alone within the
/// protocol's bounds (`ExportRows::check`), and together; the rest
/// `(file, line)`, lost. The WAL already holds a batch to them (its bytes,
/// order, blank lines): this is the core's last check before it sends.
fn sendable(
    sink: ExportSink,
    chain: ExportChain,
    rows: Vec<ExportRow>,
    hashes: Vec<String>,
) -> (Vec<ExportRow>, Vec<String>, Vec<(u64, u64)>) {
    let alone = |r: &ExportRow| {
        ExportRows {
            sink,
            chain,
            rows: vec![r.clone()],
            budget_ms: BUDGET.as_millis() as u32,
        }
        .check()
        .is_ok()
    };
    let mut kept = Vec::with_capacity(rows.len());
    let mut kept_hashes = Vec::with_capacity(rows.len());
    let mut dropped = Vec::new();
    for (r, h) in rows.into_iter().zip(hashes) {
        if alone(&r) {
            kept.push(r);
            kept_hashes.push(h);
        } else {
            dropped.push((r.file, r.line));
        }
    }
    // together: the longest prefix the check takes (the rest is read again)
    let together = |rows: &[ExportRow]| {
        ExportRows {
            sink,
            chain,
            rows: rows.to_vec(),
            budget_ms: BUDGET.as_millis() as u32,
        }
        .check()
        .is_ok()
    };
    while kept.len() > 1 && !together(&kept) {
        kept.pop();
        kept_hashes.pop();
    }
    (kept, kept_hashes, dropped)
}

/// How often the core measures the export's directory.
const DIR_CHECK_EVERY: Duration = Duration::from_secs(1);

/// Why the export's directory is past what the file sink may hold (the
/// review of #499, D5: a worker taken over could fill the chains' disk),
/// or `None`: its files are the sink's names alone (`export.jsonl`,
/// `export.jsonl.N`, `N` < `max_files`) and their total within `bound`.
/// Read as the core's export thread can — no capability: the directory is
/// world-readable, its files are not.
fn over_bound(dir: &std::path::Path, max_files: u8, bound: u64) -> Option<String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("{} not readable: {e}", dir.display())),
    };
    let mut total = 0u64;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ours = name == nn_export::jsonl::ACTIVE
            || name
                .strip_prefix(nn_export::jsonl::ACTIVE)
                .and_then(|n| n.strip_prefix('.'))
                .and_then(|n| n.parse::<u8>().ok())
                .is_some_and(|n| n >= 1 && n < max_files);
        if !ours {
            return Some(format!("a file the sink does not write: {name}"));
        }
        total += e.metadata().map(|m| m.len()).unwrap_or(0);
    }
    (total > bound).then(|| format!("{total} bytes, past its bound of {bound}"))
}

/// The least a sink down or failed waits before its next request.
const MIN_SINK_WAIT: Duration = Duration::from_millis(200);

/// How long a sink down or failed waits: the worker's retry, never less
/// than [`MIN_SINK_WAIT`] — a sink that says retry at once (a `Failed`
/// one: 0) would otherwise be asked again and again, the controller never
/// idle (the review of #499, D8).
fn sink_wait(retry_ms: u32) -> Duration {
    Duration::from_millis(u64::from(retry_ms)).max(MIN_SINK_WAIT)
}

/// Whether a request's error means the worker is set up again: it died,
/// hung or lied, and the supervisor starts another. Never for a busy slot,
/// nor for the core's own request out of its bounds (never sent: the
/// worker is not at fault — lot 276's lab, where each such setup was a new
/// connection and the rows on it written again and again; the chain waits
/// for the next round, from its cursor).
fn sets_up_again(e: &WorkerError) -> bool {
    !matches!(e, WorkerError::Busy | WorkerError::Refused(_))
}

/// One request for one chain of one sink; whether it moved anything.
fn round(p: &Params, k: &mut SinkRun, i: usize, set_up_for: &mut Option<u64>) -> bool {
    let sink = k.sink;
    let c = &mut k.chains[i];
    let batch = if c.window.len() < MAX_WINDOW {
        match wal::read_after::<LinuxHost>(
            &c.src,
            &c.next,
            c.unchecked,
            wal::Limits {
                rows: MAX_EXPORT_ROWS.min(MAX_WINDOW - c.window.len()),
                bytes: MAX_EXPORT_BYTES,
            },
            &p.pubkey,
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!(chain = c.src.chain.name(), error = %e, "export: the chain was not read");
                return false;
            }
        }
    } else {
        wal::Batch::default()
    };
    c.unchecked = false;
    if batch.lost > 0 || !batch.notes.is_empty() {
        c.lost += batch.lost;
        for n in &batch.notes {
            warn!(sink = sink.name(), chain = c.src.chain.name(), note = ?n, "export: the chain moved under the cursor");
            let mut x = note_json(n);
            if let Some(o) = x.as_object_mut() {
                o.insert("at".into(), "note".into());
                o.insert("sink".into(), sink.name().into());
                o.insert("chain".into(), c.src.chain.name().into());
            }
            sign(&p.audit, "detected", x);
        }
    }
    if batch.rows.is_empty() && c.window.is_empty() {
        // nothing in flight: skipped rows (lost, a cursor gone) move the
        // cursor too
        if let Some(n) = batch.next {
            if n != c.cursor {
                c.cursor = n.clone();
                c.dirty = true;
            }
            c.next = n;
        }
        return false;
    }
    // what the protocol's check would refuse is never sent: a row no
    // request carries is lost here, counted (stage 8) and signed, and the
    // rest goes — the window holds only what was sent (the review of #499,
    // D3: a refused request read again every round, the window cleared
    // under rows the worker still held)
    let next_after = batch.next.clone();
    let (rows, hashes, dropped) = sendable(sink, c.src.chain, batch.rows, batch.hashes);
    if !dropped.is_empty() {
        c.lost += dropped.len() as u64;
        for (file, line) in &dropped {
            warn!(
                sink = sink.name(),
                chain = c.src.chain.name(),
                file,
                line,
                "export: a row no request carries, lost"
            );
            sign(
                &p.audit,
                "detected",
                serde_json::json!({
                    "at": "note", "note": "unsendable", "sink": sink.name(),
                    "chain": c.src.chain.name(), "file": file, "line": line,
                }),
            );
        }
    }
    if rows.is_empty() {
        if let Some(n) = next_after {
            if c.window.is_empty() && n != c.cursor {
                c.cursor = n.clone();
                c.dirty = true;
            }
            c.next = n;
        }
        return false;
    }
    let batch_hashes = hashes;
    let req = ExportRows {
        sink,
        chain: c.src.chain,
        rows,
        budget_ms: BUDGET.as_millis() as u32,
    };
    let answer = p.workers.request(
        WorkerKind::Export,
        &Request::ExportRows(req.clone()),
        BUDGET + MARGIN,
    );
    let out = match answer {
        Ok(Answer::ExportRows(out)) => out,
        Ok(_) => return false, // the protocol's check refuses another kind
        Err(e) if !sets_up_again(&e) => {
            if let WorkerError::Refused(why) = &e {
                // never sent (`sendable` keeps this from happening): the
                // worker's state did not change, the window stays; the
                // rows are skipped, counted, so that no round repeats them
                k.faults += 1;
                c.lost += req.rows.len() as u64;
                warn!(sink = sink.name(), chain = c.src.chain.name(), %why, "export: a request out of its bounds was not sent");
                sign(
                    &p.audit,
                    "detected",
                    serde_json::json!({
                        "at": "note", "note": "unsendable", "sink": sink.name(),
                        "chain": c.src.chain.name(), "rows": req.rows.len(), "why": why,
                    }),
                );
                if let Some(n) = next_after {
                    c.next = n;
                }
            }
            return false;
        }
        Err(e) => {
            // the worker died, hung or lied: the supervisor starts another,
            // which gets a setup; this sink starts again from its cursors
            k.faults += 1;
            warn!(sink = sink.name(), error = %e, "export: the worker did not answer");
            *set_up_for = None;
            return false;
        }
    };
    let sent: Vec<Sent> = req
        .rows
        .iter()
        .zip(batch_hashes)
        .map(|(r, h)| Sent {
            pos: r.pos(),
            end: r.end,
            hash: h,
        })
        .collect();
    let applied = match apply(c, sent, &out) {
        Ok(a) => a,
        Err(why) => {
            p.workers.condemn(WorkerKind::Export, why);
            k.faults += 1;
            *set_up_for = None;
            return false;
        }
    };
    let moved = applied.delivered > 0;
    if moved {
        k.rows += applied.delivered as u64;
        k.records += u64::from(out.records);
        k.unverified += u64::from(out.unverified);
        k.last_delivery = Some(now_rfc3339());
    }
    k.state = Some(out.state);
    k.fault = out.fault;
    if out.fault.is_some() && !moved {
        k.faults += 1;
    }
    if out.fault == Some(SinkFault::NotSetUp) {
        // a worker that lost its setup (it cannot: a new worker gets one
        // before its first rows): set it up again
        *set_up_for = None;
    } else if out.state == SinkState::Down || out.state == SinkState::Failed {
        k.until = Some(Instant::now() + sink_wait(out.retry_ms));
    }
    moved || !req.rows.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(line: u64) -> Sent {
        Sent {
            pos: RowPos { file: 1, line },
            end: line * 10,
            hash: format!("{line:064}"),
        }
    }

    fn chain() -> ChainRun {
        ChainRun {
            src: Source {
                chain: ExportChain::Detections,
                active: PathBuf::from("/nonexistent/detections.jsonl"),
            },
            cursor: Cursor::start_of(1),
            unchecked: false,
            window: VecDeque::new(),
            next: Cursor::start_of(1),
            lost: 0,
            dirty: false,
        }
    }

    fn out(acked: Option<u64>, committed: Option<u64>, records: u32) -> ExportRowsOut {
        let at = |l: Option<u64>| l.map(|line| RowPos { file: 1, line });
        ExportRowsOut {
            acked: at(acked),
            committed: at(committed),
            records,
            unverified: 0,
            state: SinkState::Up,
            fault: None,
            retry_ms: 0,
        }
    }

    /// The window: rows acked leave it and move the cursor, the next read
    /// starts after the last committed, rows past it are read again.
    #[test]
    fn an_answer_moves_the_cursor_and_the_next_read() {
        let mut c = chain();
        let a = apply(
            &mut c,
            (1..=5).map(sent).collect(),
            &out(Some(2), Some(4), 3),
        )
        .unwrap();
        assert_eq!(a.delivered, 2);
        assert_eq!(c.cursor.pos(), RowPos { file: 1, line: 2 });
        assert_eq!(c.cursor.hash, format!("{:064}", 2));
        assert_eq!(c.cursor.end, 20);
        assert!(c.dirty);
        assert_eq!(
            c.window.iter().map(|s| s.pos.line).collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(c.next.pos(), RowPos { file: 1, line: 4 });
        // a poll: the rest acked
        let a = apply(&mut c, vec![], &out(Some(4), Some(4), 2)).unwrap();
        assert_eq!(a.delivered, 2);
        assert!(c.window.is_empty());
        assert_eq!(c.next, c.cursor);
        // the worker went back (its connection lost): read again from the
        // cursor
        let mut c = chain();
        apply(&mut c, (1..=3).map(sent).collect(), &out(None, Some(3), 0)).unwrap();
        assert_eq!(c.next.pos().line, 3);
        let a = apply(&mut c, vec![], &out(None, None, 0)).unwrap();
        assert_eq!(a.delivered, 0);
        assert!(c.window.is_empty());
        assert_eq!(c.next, Cursor::start_of(1));
    }

    /// A row never sent, or records beyond the rows: a lie.
    #[test]
    fn an_answer_beyond_what_was_sent_is_refused() {
        let mut c = chain();
        assert!(apply(
            &mut c,
            (1..=2).map(sent).collect(),
            &out(Some(3), Some(3), 0)
        )
        .is_err());
        assert!(c.window.is_empty(), "the window is dropped");
        let mut c = chain();
        assert!(apply(&mut c, (1..=2).map(sent).collect(), &out(None, Some(7), 0)).is_err());
        let mut c = chain();
        assert!(apply(
            &mut c,
            (1..=2).map(sent).collect(),
            &out(Some(1), Some(2), 3)
        )
        .is_err());
        // two records a row is the most
        let mut c = chain();
        assert!(apply(
            &mut c,
            (1..=2).map(sent).collect(),
            &out(Some(2), Some(2), 4)
        )
        .is_ok());
        // a row at or before the cursor is no lie (an ack already applied)
        let mut c = chain();
        c.cursor = sent(5).cursor();
        assert!(apply(&mut c, vec![], &out(Some(4), Some(5), 0)).is_ok());
        assert_eq!(c.cursor.pos().line, 5, "the cursor never goes back");
    }

    #[test]
    fn a_row_no_request_carries_is_dropped_the_rest_sent() {
        let row = |line: u64, raw: &[u8]| ExportRow {
            file: 1,
            line,
            end: 100 * line,
            raw: raw.to_vec(),
            rotate: None,
        };
        let h = |n: usize| (0..n).map(|i| format!("h{i}")).collect::<Vec<_>>();
        // a blank row in the middle: dropped, the others kept in order
        let (kept, hashes, dropped) = sendable(
            ExportSink::File,
            ExportChain::Detections,
            vec![row(1, b"{}"), row(2, b""), row(3, b"{}")],
            h(3),
        );
        assert_eq!(kept.iter().map(|r| r.line).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(hashes, ["h0", "h2"]);
        assert_eq!(dropped, [(1, 2)]);
        // out of order together: the longest prefix the check takes
        let (kept, _, dropped) = sendable(
            ExportSink::File,
            ExportChain::Detections,
            vec![row(1, b"{}"), row(3, b"{}"), row(2, b"{}")],
            h(3),
        );
        assert_eq!(kept.iter().map(|r| r.line).collect::<Vec<_>>(), [1, 3]);
        assert!(dropped.is_empty());
        // a request of what is kept always passes
        let req = ExportRows {
            sink: ExportSink::File,
            chain: ExportChain::Detections,
            rows: kept,
            budget_ms: 1000,
        };
        assert_eq!(req.check(), Ok(()));
    }

    #[test]
    fn the_export_s_directory_is_held_to_its_bound() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(over_bound(&d.path().join("none"), 3, 100), None);
        std::fs::write(d.path().join("export.jsonl"), [b'a'; 40]).unwrap();
        std::fs::write(d.path().join("export.jsonl.1"), [b'a'; 40]).unwrap();
        std::fs::write(d.path().join("export.jsonl.2"), [b'a'; 20]).unwrap();
        assert_eq!(over_bound(d.path(), 3, 100), None);
        // one byte more
        std::fs::write(d.path().join("export.jsonl.2"), [b'a'; 21]).unwrap();
        assert!(over_bound(d.path(), 3, 100)
            .unwrap()
            .contains("past its bound"));
        // a name the sink does not write, a number past its files
        std::fs::write(d.path().join("export.jsonl.2"), [b'a'; 1]).unwrap();
        for bad in [
            "export.jsonl.3",
            "filler",
            "export.jsonl.0",
            "export.jsonl.x",
        ] {
            std::fs::write(d.path().join(bad), b"x").unwrap();
            let why = over_bound(d.path(), 3, 100).unwrap();
            assert!(why.contains("does not write"), "{bad}: {why}");
            std::fs::remove_file(d.path().join(bad)).unwrap();
        }
        assert_eq!(over_bound(d.path(), 3, 100), None);
    }

    #[test]
    fn a_sink_down_or_failed_waits_at_least_its_minimum() {
        assert_eq!(sink_wait(0), Duration::from_millis(200));
        assert_eq!(sink_wait(150), Duration::from_millis(200));
        assert_eq!(sink_wait(1001), Duration::from_millis(1001));
    }

    #[test]
    fn a_refused_request_or_a_busy_slot_is_no_setup_again() {
        assert!(!sets_up_again(&WorkerError::Busy));
        assert!(!sets_up_again(&WorkerError::Refused(
            "export_rows: the request's bytes".into()
        )));
        assert!(sets_up_again(&WorkerError::Timeout));
        assert!(sets_up_again(&WorkerError::Died(
            "closed its channel".into()
        )));
        assert!(sets_up_again(&WorkerError::Violation("bounds".into())));
    }

    #[test]
    fn states_rank_and_faults_read() {
        assert!(state_rank(Some(SinkState::Failed)) > state_rank(Some(SinkState::Down)));
        assert!(state_rank(Some(SinkState::Down)) > state_rank(Some(SinkState::Up)));
        assert!(fault_text(&SinkFault::Connect(libc::ECONNREFUSED)).contains("refused"));
        assert_eq!(
            fault_text(&SinkFault::Pin),
            "the connects could not be pinned to the receiver's port"
        );
    }
}
