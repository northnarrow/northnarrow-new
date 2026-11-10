//! The export worker's state (lot 276): its setup, its two sinks, and the
//! answer to each request. Runs in the worker only, after its sandbox
//! (`nn_linux::sandbox::Profile::export`); the agent's worker entry feeds it
//! the core's requests.
//!
//! Each row is checked against the agent's key (`row_verify`: the records
//! of a row that does not verify are written all the same, flagged
//! `verified: false`, and counted), mapped (`ocsf`) and written: as JSONL
//! lines to the file sink, as RFC 5424 messages to the syslog sink.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use nn_proto::ipc::{
    ExportAddr, ExportChain, ExportRow, ExportRows, ExportRowsOut, ExportSetup, ExportSetupOut,
    ExportSink, RowPos, SinkFault, SinkState,
};
use serde_json::Value;

use crate::jsonl::JsonlSink;
use crate::net::{Framed, SyslogSink};
use crate::ocsf::{self, Context, Mapper, Row};
use crate::syslog;

/// A row's records, as lines, and whether it verified.
struct Mapped {
    lines: Vec<Vec<u8>>,
    values: Vec<Value>,
    verified: bool,
}

fn map_row(
    mapper: &mut Mapper,
    ctx: &Context,
    pk: &VerifyingKey,
    chain: ExportChain,
    r: &ExportRow,
) -> Mapped {
    let (verified, prev, entry) =
        match nn_evidence::row_verify::verify_row(&r.raw, chain.name(), pk) {
            Ok(seal) => (true, Some(seal.prev_hash), Some(seal.entry_hash)),
            Err(_) => match nn_evidence::row_verify::links(&r.raw) {
                Some((p, e)) => (false, Some(p), Some(e)),
                None => (false, None, None),
            },
        };
    let row = Row {
        chain,
        file: r.file,
        line: r.line,
        end: r.end,
        raw: &r.raw,
        rotate: r.rotate.as_deref(),
        verified,
        prev_hash: prev,
        entry_hash: entry,
    };
    let values = mapper.map(ctx, &row);
    Mapped {
        lines: values.iter().map(ocsf::to_line).collect(),
        values,
        verified,
    }
}

#[derive(Debug)]
struct FileSide {
    sink: Option<JsonlSink>,
    setup: (u64, u8),
    mapper: Mapper,
    written: std::collections::HashMap<ExportChain, RowPos>,
    fault: Option<SinkFault>,
}

#[derive(Debug)]
struct SyslogSide {
    sink: SyslogSink,
    mapper: Mapper,
    facility: u8,
}

/// The worker's state.
#[derive(Debug)]
pub struct ExportWorker {
    dir: PathBuf,
    ctx: Option<Context>,
    pk: Option<VerifyingKey>,
    file: Option<FileSide>,
    syslog: Option<SyslogSide>,
    syslog_fault: Option<SinkFault>,
    /// The receiver's port the worker's connects are pinned to (a Landlock
    /// layer of this process, laid once).
    pinned: Option<u16>,
}

fn addr(a: &ExportAddr, port: u16) -> SocketAddr {
    let ip = match a {
        ExportAddr::V4(b) => IpAddr::V4(Ipv4Addr::from(*b)),
        ExportAddr::V6(b) => IpAddr::V6(Ipv6Addr::from(*b)),
    };
    SocketAddr::new(ip, port)
}

impl ExportWorker {
    /// The worker, its file sink's directory `dir` (the one its Landlock
    /// rule names).
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            ctx: None,
            pk: None,
            file: None,
            syslog: None,
            syslog_fault: None,
            pinned: None,
        }
    }

    /// Take a setup: open the file sink, pin the connects to the
    /// receiver's port when asked (`pin`: the sandbox's Landlock layer for
    /// that port, whether it held), prepare the TLS client.
    pub fn setup(&mut self, s: &ExportSetup, pin: &mut dyn FnMut(u16) -> bool) -> ExportSetupOut {
        self.ctx = Some(Context {
            agent_id: s.agent_id.clone(),
            hostname: s.hostname.clone(),
            version: s.version.clone(),
        });
        self.pk = VerifyingKey::from_bytes(&s.pubkey).ok();
        let mut fault = None;
        self.file = s.file.as_ref().map(|f| {
            let (sink, fault) = match JsonlSink::open(&self.dir, f.max_bytes, f.max_files) {
                Ok(k) => (Some(k), None),
                Err(e) => (None, Some(SinkFault::File(e))),
            };
            FileSide {
                sink,
                setup: (f.max_bytes, f.max_files),
                mapper: Mapper::new(),
                written: Default::default(),
                fault,
            }
        });
        let file_state = match &self.file {
            None => SinkState::Off,
            Some(f) if f.sink.is_some() => SinkState::Up,
            Some(f) => {
                fault = f.fault;
                SinkState::Failed
            }
        };
        let mut port_pinned = false;
        self.syslog = None;
        self.syslog_fault = None;
        let syslog_state = match &s.syslog {
            None => SinkState::Off,
            Some(sy) => {
                // a Landlock layer cannot be taken back, and a process holds
                // at most 16: the pin is laid once, and a setup again (the
                // core sets a worker up again after a fault) reuses it —
                // for its port only
                port_pinned = match self.pinned {
                    Some(p) => p == sy.port,
                    None if sy.pin_port => {
                        let held = pin(sy.port);
                        if held {
                            self.pinned = Some(sy.port);
                        }
                        held
                    }
                    None => false,
                };
                if sy.pin_port && !port_pinned {
                    self.syslog_fault = Some(SinkFault::Pin);
                    SinkState::Failed
                } else {
                    match SyslogSink::new(addr(&sy.addr, sy.port), &sy.server_name, &sy.ca_pem) {
                        Ok(sink) => {
                            self.syslog = Some(SyslogSide {
                                sink,
                                mapper: Mapper::new(),
                                facility: sy.facility,
                            });
                            SinkState::Connecting
                        }
                        Err(f) => {
                            self.syslog_fault = Some(f);
                            SinkState::Failed
                        }
                    }
                }
            }
        };
        ExportSetupOut {
            port_pinned,
            file: file_state,
            syslog: syslog_state,
            fault: self.syslog_fault.or(fault),
        }
    }

    /// Serve one request.
    pub fn rows(&mut self, r: &ExportRows) -> ExportRowsOut {
        let deadline = Instant::now() + Duration::from_millis(u64::from(r.budget_ms));
        let (Some(ctx), Some(pk)) = (self.ctx.clone(), self.pk) else {
            return failed(SinkFault::NotSetUp);
        };
        match r.sink {
            ExportSink::File => match self.file.as_mut() {
                None => failed(SinkFault::NotSetUp),
                Some(f) => file_rows(f, &self.dir, &ctx, &pk, r),
            },
            ExportSink::Syslog => match self.syslog.as_mut() {
                None => failed(self.syslog_fault.unwrap_or(SinkFault::NotSetUp)),
                Some(s) => {
                    let SyslogSide {
                        sink,
                        mapper,
                        facility,
                    } = s;
                    let facility = *facility;
                    let d = sink.rows(
                        r.chain,
                        &r.rows,
                        |row| (row.file, row.line),
                        |row| {
                            let m = map_row(mapper, &ctx, &pk, r.chain, row);
                            let frames = m
                                .values
                                .iter()
                                .zip(&m.lines)
                                .map(|(v, line)| {
                                    syslog::frame(&syslog::message(
                                        facility,
                                        v["severity_id"].as_u64().unwrap_or(0) as u8,
                                        v["time"].as_i64().unwrap_or(0),
                                        &ctx.hostname,
                                        v["class_uid"].as_u64().unwrap_or(0),
                                        line,
                                    ))
                                })
                                .collect();
                            Framed {
                                frames,
                                records: m.values.len() as u32,
                                verified: m.verified,
                            }
                        },
                        deadline,
                    );
                    let pos = |p: Option<(u64, u64)>| p.map(|(file, line)| RowPos { file, line });
                    ExportRowsOut {
                        acked: pos(d.acked),
                        committed: pos(d.committed),
                        records: d.records,
                        unverified: d.unverified,
                        state: d.state,
                        fault: d.fault,
                        retry_ms: d.retry_ms,
                    }
                }
            },
        }
    }
}

fn failed(fault: SinkFault) -> ExportRowsOut {
    ExportRowsOut {
        acked: None,
        committed: None,
        records: 0,
        unverified: 0,
        state: SinkState::Failed,
        fault: Some(fault),
        retry_ms: 0,
    }
}

fn file_rows(
    f: &mut FileSide,
    dir: &Path,
    ctx: &Context,
    pk: &VerifyingKey,
    r: &ExportRows,
) -> ExportRowsOut {
    if f.sink.is_none() {
        match JsonlSink::open(dir, f.setup.0, f.setup.1) {
            Ok(k) => {
                f.sink = Some(k);
                f.fault = None;
            }
            Err(e) => f.fault = Some(SinkFault::File(e)),
        }
    }
    let before = f.written.get(&r.chain).copied();
    let mut lines = Vec::new();
    let (mut records, mut unverified) = (0u32, 0u32);
    let mut last = before;
    for row in &r.rows {
        if before.is_some_and(|b| row.pos() <= b) {
            continue;
        }
        let m = map_row(&mut f.mapper, ctx, pk, r.chain, row);
        records += m.lines.len() as u32;
        unverified += u32::from(!m.verified);
        lines.extend(m.lines);
        last = Some(row.pos());
    }
    let result = match f.sink.as_mut() {
        None => Err(f.fault.unwrap_or(SinkFault::File(libc::EIO))),
        Some(_) if lines.is_empty() => Ok(()),
        Some(k) => k.write(&lines).map_err(SinkFault::File),
    };
    match result {
        Ok(()) => {
            f.fault = None;
            if let Some(l) = last {
                f.written.insert(r.chain, l);
            }
            ExportRowsOut {
                acked: last,
                committed: last,
                records,
                unverified,
                state: SinkState::Up,
                fault: None,
                retry_ms: 0,
            }
        }
        Err(fault) => {
            // nothing of this batch counts: written again next time — by the
            // same sink (lot 296, BUG31): it knows whether its last write
            // stopped inside a line, which a sink opened again does not
            f.fault = Some(fault);
            ExportRowsOut {
                acked: before,
                committed: before,
                records: 0,
                unverified: 0,
                state: SinkState::Down,
                fault: Some(fault),
                retry_ms: 1000,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_proto::ipc::{FileSetup, SyslogSetup};

    fn setup(file: bool, syslog: bool, pin_port: bool) -> ExportSetup {
        ExportSetup {
            agent_id: "0123456789abcdef0123456789abcdef".into(),
            hostname: "lab".into(),
            version: "0.0.1".into(),
            pubkey: ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes(),
            file: file.then_some(FileSetup {
                max_bytes: 1 << 20,
                max_files: 2,
            }),
            syslog: syslog.then(|| SyslogSetup {
                addr: ExportAddr::V4([127, 0, 0, 1]),
                port: 9,
                server_name: "receiver.lab".into(),
                ca_pem: crate::tls::tests::CA_PEM.as_bytes().to_vec(),
                facility: 13,
                pin_port,
            }),
        }
    }

    fn row(line: u64, raw: &str) -> ExportRow {
        ExportRow {
            file: 1,
            line,
            end: line * 100,
            raw: raw.as_bytes().to_vec(),
            rotate: None,
        }
    }

    fn rows(sink: ExportSink, rows: Vec<ExportRow>) -> ExportRows {
        ExportRows {
            sink,
            chain: ExportChain::Detections,
            rows,
            budget_ms: 500,
        }
    }

    #[test]
    fn no_setup_no_export() {
        let d = tempfile::tempdir().unwrap();
        let mut w = ExportWorker::new(d.path());
        let o = w.rows(&rows(ExportSink::File, vec![row(1, "{}")]));
        assert_eq!(o.fault, Some(SinkFault::NotSetUp));
        assert_eq!(o.state, SinkState::Failed);
        assert_eq!(o.acked, None);
    }

    /// The file sink: each row's records as lines, the row unverified
    /// (signed by another key) flagged, a row given again not written
    /// twice; a directory that is gone fails the batch and nothing of it
    /// counts.
    #[test]
    fn the_file_sink_writes_each_row_once() {
        let d = tempfile::tempdir().unwrap();
        let mut w = ExportWorker::new(d.path());
        let out = w.setup(&setup(true, false, false), &mut |_| false);
        assert_eq!(
            (out.file, out.syslog, out.port_pinned, out.fault),
            (SinkState::Up, SinkState::Off, false, None)
        );
        let fx = crate::ocsf::tests::fixtures();
        let req = rows(
            ExportSink::File,
            vec![row(1, &fx[0].1), row(2, &fx[1].1), row(3, "garbage")],
        );
        let o = w.rows(&req);
        assert_eq!(o.acked, Some(RowPos { file: 1, line: 3 }));
        assert_eq!(o.committed, o.acked);
        assert_eq!(
            (o.records, o.unverified),
            (4, 3),
            "2 + 1 + 1 records; none signed by the key"
        );
        let text = std::fs::read_to_string(d.path().join(crate::jsonl::ACTIVE)).unwrap();
        assert_eq!(text.lines().count(), 4);
        for l in text.lines() {
            let v: Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["unmapped"]["northnarrow"]["row"]["verified"], false);
            assert!(crate::schema::check_record(&v).is_empty());
        }
        // the same rows again (a core that went back): nothing written
        let o = w.rows(&req);
        assert_eq!(o.acked, Some(RowPos { file: 1, line: 3 }));
        assert_eq!(o.records, 0);
        assert_eq!(
            std::fs::read_to_string(d.path().join(crate::jsonl::ACTIVE))
                .unwrap()
                .lines()
                .count(),
            4
        );
        // the directory gone: the batch fails, its rows are not acked
        drop(w);
        let gone = tempfile::tempdir().unwrap();
        let mut w = ExportWorker::new(&gone.path().join("export"));
        let out = w.setup(&setup(true, false, false), &mut |_| false);
        assert_eq!(out.file, SinkState::Failed);
        assert_eq!(out.fault, Some(SinkFault::File(libc::ENOENT)));
        let o = w.rows(&rows(ExportSink::File, vec![row(1, "{}")]));
        assert_eq!((o.acked, o.state), (None, SinkState::Down));
        assert_eq!(o.fault, Some(SinkFault::File(libc::ENOENT)));
        // once it exists the sink opens at the next request
        std::fs::create_dir(gone.path().join("export")).unwrap();
        let o = w.rows(&rows(ExportSink::File, vec![row(1, "{}")]));
        assert_eq!(
            (o.acked, o.state),
            (Some(RowPos { file: 1, line: 1 }), SinkState::Up)
        );
    }

    /// Lot 296 (BUG31): the writer of
    /// [`a_batch_written_again_after_a_partial_write_is_whole_lines`], in a
    /// process of its own — the file size limit (`RLIMIT_FSIZE`, the
    /// kernel's own short write, as a full disk makes it) is the process's:
    /// the test's threads must not see it. A no-op without its variable.
    #[test]
    #[ignore = "a helper: run by a_batch_written_again_after_a_partial_write_is_whole_lines"]
    fn partial_write_worker() {
        let Some(dir) = std::env::var_os("NN_EXPORT_PARTIAL_WRITE_DIR") else {
            return;
        };
        let mut w = ExportWorker::new(Path::new(&dir));
        let out = w.setup(&setup(true, false, false), &mut |_| false);
        assert_eq!(out.file, SinkState::Up);
        let fx = crate::ocsf::tests::fixtures();
        let req = rows(ExportSink::File, vec![row(1, &fx[0].1)]);
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: signal/getrlimit/setrlimit with valid arguments, in this
        // helper process alone; the limit is put back at once.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut old), 0);
            let low = libc::rlimit {
                rlim_cur: 100,
                rlim_max: old.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &low), 0);
        }
        let o = w.rows(&req);
        // SAFETY: as above.
        unsafe {
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &old), 0);
        }
        assert_eq!(
            (o.acked, o.state, o.fault),
            (None, SinkState::Down, Some(SinkFault::File(libc::EFBIG)))
        );
        // space back: the core gives the batch again
        let o = w.rows(&req);
        assert_eq!(
            (o.acked, o.state, o.fault, o.records),
            (Some(RowPos { file: 1, line: 1 }), SinkState::Up, None, 2)
        );
    }

    /// Lot 296 (BUG31): a batch the file took part of (a full disk) is Down
    /// and not acknowledged; written again, each of its records is a line of
    /// its own — the worker kept its sink, which closes the start of a line
    /// its last write left. A sink opened again knew nothing of it, and the
    /// first record, acknowledged, was glued to that start.
    #[test]
    fn a_batch_written_again_after_a_partial_write_is_whole_lines() {
        let d = tempfile::tempdir().unwrap();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "worker::tests::partial_write_worker",
                "--test-threads=1",
            ])
            .env("NN_EXPORT_PARTIAL_WRITE_DIR", d.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "the writer: {st}");
        let text = std::fs::read_to_string(d.path().join(crate::jsonl::ACTIVE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "the start of a record, then two: {} line(s)",
            lines.len()
        );
        assert_eq!(lines[0].len(), 100);
        assert!(serde_json::from_str::<Value>(lines[0]).is_err());
        for l in &lines[1..] {
            let v: Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"));
            assert!(crate::schema::check_record(&v).is_empty());
        }
    }

    /// The pin: asked for and refused, the syslog sink connects nowhere;
    /// laid once per worker; not asked for (an older kernel), not tried.
    #[test]
    fn the_receiver_s_port_is_pinned_before_any_connect() {
        let d = tempfile::tempdir().unwrap();
        let mut w = ExportWorker::new(d.path());
        let mut asked = Vec::new();
        let out = w.setup(&setup(false, true, true), &mut |p| {
            asked.push(p);
            false
        });
        assert_eq!(asked, vec![9]);
        assert_eq!(
            (out.syslog, out.port_pinned, out.fault),
            (SinkState::Failed, false, Some(SinkFault::Pin))
        );
        let o = w.rows(&rows(ExportSink::Syslog, vec![row(1, "{}")]));
        assert_eq!(o.fault, Some(SinkFault::Pin));
        assert_eq!(o.acked, None);
        let mut laid = 0;
        let out = w.setup(&setup(false, true, true), &mut |_| {
            laid += 1;
            true
        });
        assert_eq!(
            (out.syslog, out.port_pinned, out.fault),
            (SinkState::Connecting, true, None)
        );
        // set up again (the core does after a fault): the layer laid once
        // holds — never another (a process holds at most 16 of them)
        for _ in 0..20 {
            let out = w.setup(&setup(false, true, true), &mut |_| {
                laid += 1;
                true
            });
            assert_eq!((out.syslog, out.port_pinned), (SinkState::Connecting, true));
        }
        assert_eq!(laid, 1);
        // another port: the pin it holds is not that one's
        let mut other = setup(false, true, true);
        other.syslog.as_mut().unwrap().port = 10;
        let out = w.setup(&other, &mut |_| panic!("a second layer"));
        assert_eq!(
            (out.syslog, out.port_pinned, out.fault),
            (SinkState::Failed, false, Some(SinkFault::Pin))
        );
        // not asked for (an older kernel): no layer tried
        let mut w2 = ExportWorker::new(d.path());
        let out = w2.setup(&setup(false, true, false), &mut |_| panic!("not asked"));
        assert_eq!(
            (out.syslog, out.port_pinned),
            (SinkState::Connecting, false)
        );
        // a CA bundle with no certificate
        let mut bad = setup(false, true, false);
        bad.syslog.as_mut().unwrap().ca_pem = b"nothing".to_vec();
        let out = w.setup(&bad, &mut |_| true);
        assert_eq!(
            (out.syslog, out.fault),
            (SinkState::Failed, Some(SinkFault::BadTrust))
        );
    }

    /// A row signed by the setup's key verifies; the record says so.
    #[test]
    fn rows_are_verified_with_the_agent_s_key() {
        let d = tempfile::tempdir().unwrap();
        // a real rotating log's line, signed by the key the setup names
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct P {
            id: u64,
            ts: String,
            sensor: String,
        }
        impl nn_evidence::chainlog::ChainPayload for P {
            const KIND: &'static str = "detections";
        }
        let logdir = tempfile::tempdir().unwrap();
        let active = logdir.path().join("detections.jsonl");
        let mut log = nn_evidence::chainlog::RotatingChainLog::<P, _>::open(
            &active,
            crate::testing::TestKey::new(3),
            nn_evidence::chainlog::RotationConfig::default(),
            std::sync::Arc::new(nn_evidence::chainlog::NoProtection),
        )
        .unwrap();
        log.append(P {
            id: 1,
            ts: "2026-11-03T00:00:00.000000Z".into(),
            sensor: "File".into(),
        })
        .unwrap();
        drop(log);
        let line = std::fs::read_to_string(&active).unwrap();
        let mut w = ExportWorker::new(d.path());
        w.setup(&setup(true, false, false), &mut |_| false);
        let o = w.rows(&rows(ExportSink::File, vec![row(1, line.trim_end())]));
        assert_eq!((o.records, o.unverified), (1, 0));
        let v: Value = serde_json::from_str(
            std::fs::read_to_string(d.path().join(crate::jsonl::ACTIVE))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let at = &v["unmapped"]["northnarrow"]["row"];
        assert_eq!(at["verified"], true);
        assert_eq!(at["entry_hash"].as_str().unwrap().len(), 64);
        assert_eq!(v["raw_data"], line.trim_end());
    }
}
