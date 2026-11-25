//! Lot 1.6 (Dependabot #613: postcard 1.1.3 → 1.2.0): the bytes postcard
//! writes for this repository's own wire types, pinned as postcard 1.1.3
//! wrote them. postcard's wire format is stable within 1.x; this test is
//! the proof on our types, beside the admin frames
//! `admin_protocol::encoded_frames_are_pinned` already holds.
//!
//! The values sit on varint boundaries — 127/128 and 16383/16384, `u32::MAX`
//! and `u64::MAX`, a string and a byte vector whose lengths take two varint
//! bytes — through every shape the protocols use: unit, newtype and struct
//! enum variants, `Option` both ways, fixed arrays, tuples in a vector,
//! booleans. Each frame also decodes back to its value.
//!
//! Lot 1.8 (the review of #615, P3): the core ↔ export worker messages of
//! `nn_proto::ipc` (the worker's hello, a ping and its pong, the export's
//! setup and rows, their answers, a refusal), written by `ipc::encode`, and
//! the watchdog's loop-progress exchange with the agent (its request and the
//! agent's reply, read back by `decode_loop_progress` as the watchdog reads
//! it, an older agent's two-field reply too): the same check, the bytes
//! postcard 1.1.3 wrote for them (generated on the tree before #615, with
//! postcard 1.1.3 locked, and equal there).

use nn_proto::admin_protocol::{
    AdminMessage, AdminResult, LoopProgressRequest, LoopProgressResponse, NetResolveResponse,
    RecordsToday, decode_frame, decode_loop_progress, encode_frame,
};
use nn_proto::execq::{
    self, FromScanner, HashEntry, Reason, ScanConfig, ScanRequest, ScanResult, ScanVerdict,
    ScannerHello, ToScanner,
};
use nn_proto::ipc::{
    self, Answer, EXPORT_DIR_RULE, ExportAddr, ExportChain, ExportRow, ExportRows, ExportRowsOut,
    ExportSetup, ExportSetupOut, ExportSink, FileSetup, FromWorker, LandlockEnforced, Refusal,
    Request, Response, RowPos, SandboxLevel, SinkFault, SinkState, SyslogSetup, TlsFault, ToWorker,
    WorkerHello, WorkerKind,
};

fn configure() -> ToScanner {
    ToScanner::Configure {
        version: u32::MAX,
        config_len: u64::MAX,
    }
}

fn scan() -> ToScanner {
    ToScanner::Scan(ScanRequest {
        id: 127,
        class: 128,
        path_hint: "/usr/bin/".repeat(15),
    })
}

fn result() -> FromScanner {
    FromScanner::Result(ScanResult {
        id: 16_383,
        sha256: [0x7e; 32],
        size: 16_384,
        verdict: ScanVerdict::Malicious,
        reasons: vec![Reason::new("yara", "rule x", 300), Reason::new("", "", 0)],
        format: "ELF".into(),
        micros: 1 << 56,
    })
}

fn ready() -> FromScanner {
    FromScanner::Ready(ScannerHello {
        version: 1,
        engine: "nn-scan".into(),
        uid: 65_534,
        seccomp: true,
        block_entries: 0,
        allow_entries: 2_097_152,
        yara: String::new(),
    })
}

fn refused() -> FromScanner {
    FromScanner::Refused {
        id: 0,
        reason: "too big".into(),
    }
}

fn config(rules: Option<Vec<u8>>) -> ScanConfig {
    ScanConfig {
        block: vec![HashEntry {
            sha256: [0x01; 32],
            label: "b".into(),
        }],
        allow: Vec::new(),
        suspicious_threshold: 2_097_151,
        max_read_bytes: 268_435_456,
        max_hash_bytes: 0,
        yara_rules: rules,
    }
}

fn resolved(qname: Option<&str>, at: Option<u64>) -> AdminMessage {
    AdminMessage::NetResolveResponse(NetResolveResponse {
        result: AdminResult::Success,
        qname: qname.map(str::to_string),
        queried_at_unix_ts: at,
    })
}

fn records_today() -> RecordsToday {
    RecordsToday {
        day: "2026-11-25".into(),
        since: "2026-11-25T00:00:00Z".into(),
        by_severity: vec![("Critical".into(), 1), ("Low".into(), 129)],
        would_have: vec![("KillProcessTree".into(), 16_384)],
    }
}

fn hello() -> FromWorker {
    FromWorker::Hello(WorkerHello {
        version: 4,
        kind: WorkerKind::Export,
        pid: 16_384,
        sandbox: SandboxLevel {
            landlock_abi: 6,
            landlock: LandlockEnforced::Full,
            fs_denied: true,
            net_denied: true,
            scoped: true,
            seccomp: true,
            no_new_privs: true,
            dumpable: false,
            uid: 997,
            gid: 128,
            groups: 0,
            cap_eff: 0,
            cap_prm: 0,
            cap_inh: 0,
            cap_amb: 0,
            cap_bnd: (1 << 41) - 1,
            nofile: 1_024,
            nproc: 127,
            core: 0,
            fs_rules: vec![EXPORT_DIR_RULE.into()],
        },
    })
}

fn ping() -> ToWorker {
    ToWorker {
        id: 127,
        req: Request::Ping,
    }
}

fn pong() -> FromWorker {
    FromWorker::Response(Response {
        id: 127,
        answer: Answer::Pong,
    })
}

fn export_setup(syslog: bool) -> ToWorker {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    addr[15] = 1;
    ToWorker {
        id: 128,
        req: Request::ExportSetup(ExportSetup {
            agent_id: "0123456789abcdef0123456789abcdef".into(),
            hostname: "host-1.lab".into(),
            version: "0.1.0-alpha".into(),
            pubkey: [0x5a; 32],
            file: Some(FileSetup {
                max_bytes: 64 << 20,
                max_files: 32,
            }),
            syslog: syslog.then(|| SyslogSetup {
                addr: ExportAddr::V6(addr),
                port: 6_514,
                server_name: "receiver.lab".into(),
                ca_pem: vec![b'-'; 130],
                facility: 16,
                pin_port: true,
            }),
        }),
    }
}

fn export_rows() -> ToWorker {
    ToWorker {
        id: 16_384,
        req: Request::ExportRows(ExportRows {
            sink: ExportSink::Syslog,
            chain: ExportChain::Netflow,
            rows: vec![
                ExportRow {
                    file: 0,
                    line: 127,
                    end: 16_384,
                    raw: vec![b'{'; 128],
                    rotate: None,
                },
                ExportRow {
                    file: 1 << 32,
                    line: 1,
                    end: u64::MAX,
                    raw: b"}".to_vec(),
                    rotate: Some(b"rot".to_vec()),
                },
            ],
            budget_ms: 3_000,
        }),
    }
}

fn setup_answer() -> FromWorker {
    FromWorker::Response(Response {
        id: 128,
        answer: Answer::ExportSetup(ExportSetupOut {
            port_pinned: true,
            file: SinkState::Up,
            syslog: SinkState::Connecting,
            fault: None,
        }),
    })
}

fn rows_answer(fault: SinkFault) -> FromWorker {
    let down = matches!(fault, SinkFault::Connect(_));
    FromWorker::Response(Response {
        id: 16_384,
        answer: Answer::ExportRows(ExportRowsOut {
            acked: down.then_some(RowPos { file: 0, line: 127 }),
            committed: down.then_some(RowPos {
                file: 1 << 32,
                line: 1,
            }),
            records: 2,
            unverified: u32::MAX,
            state: if down {
                SinkState::Down
            } else {
                SinkState::Failed
            },
            fault: Some(fault),
            retry_ms: 120_000,
        }),
    })
}

fn refusal() -> FromWorker {
    FromWorker::Response(Response {
        id: u64::MAX,
        answer: Answer::Refused(Refusal::OutOfBounds),
    })
}

fn loop_progress() -> LoopProgressResponse {
    LoopProgressResponse {
        iterations: 1 << 35,
        since_last_ms: 16_384,
        unsigned_ms: 127,
    }
}

/// The frames, named, as postcard 1.1.3 wrote them (hex).
const PINNED: &[(&str, &str)] = &[
    ("execq configure", "00ffffffff0fffffffffffffffffff01"),
    (
        "execq scan",
        concat!(
            "017f800187012f7573722f62696e2f2f7573722f62696e2f2f7573722f62696e2f2f7573",
            "722f62696e2f2f7573722f62696e2f2f7573722f62696e2f2f7573722f62696e2f2f7573",
            "722f62696e2f2f7573722f62696e2f2f7573722f62696e2f2f7573722f62696e2f2f7573",
            "722f62696e2f2f7573722f62696e2f2f7573722f62696e2f2f7573722f62696e2f",
        ),
    ),
    (
        "execq result",
        concat!(
            "01ff7f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e80",
            "8001030204796172610672756c652078ac0200000003454c46808080808080808001",
        ),
    ),
    ("execq ready", "0001076e6e2d7363616efeff0301008080800100"),
    ("execq refused", "020007746f6f20626967"),
    (
        "execq config, rules",
        concat!(
            "010101010101010101010101010101010101010101010101010101010101010101016200",
            "ffff7f808080800100018201a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        ),
    ),
    (
        "execq config, none",
        concat!(
            "010101010101010101010101010101010101010101010101010101010101010101016200",
            "ffff7f80808080010000",
        ),
    ),
    (
        "admin net resolve",
        "000000152100010b6578616d706c652e6f72670180f2d6ca06",
    ),
    ("admin net resolve, none", "0000000421000000"),
    (
        "records today",
        concat!(
            "0a323032362d31312d323514323032362d31312d32355430303a30303a30305a02084372",
            "69746963616c01034c6f778101010f4b696c6c50726f6365737354726565808001",
        ),
    ),
    (
        "ipc hello",
        concat!(
            "0004018080010600010101010100e50780010000000000ffffffffff3f80087f0001422f",
            "7661722f6c6f672f6e6f7274686e6172726f772f6578706f72743a20726561642c207772",
            "6974652c206372656174652c2072656d6f76652c207472756e63617465",
        ),
    ),
    ("ipc ping", "7f00"),
    ("ipc pong", "017f00"),
    (
        "ipc export setup",
        concat!(
            "800104203031323334353637383961626364656630313233343536373839616263646566",
            "0a686f73742d312e6c61620b302e312e302d616c7068615a5a5a5a5a5a5a5a5a5a5a5a5a",
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a018080802020010120010db80000000000",
            "00000000000001f2320c72656365697665722e6c616282012d2d2d2d2d2d2d2d2d2d2d2d",
            "2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d",
            "2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d",
            "2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d",
            "2d2d2d2d2d2d2d2d2d2d1001",
        ),
    ),
    (
        "ipc export setup, file only",
        concat!(
            "800104203031323334353637383961626364656630313233343536373839616263646566",
            "0a686f73742d312e6c61620b302e312e302d616c7068615a5a5a5a5a5a5a5a5a5a5a5a5a",
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a01808080202000",
        ),
    ),
    (
        "ipc export rows",
        concat!(
            "80800105010302007f80800180017b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b",
            "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b",
            "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b",
            "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b0080",
            "8080801001ffffffffffffffffff01017d0103726f74b817",
        ),
    ),
    ("ipc export setup answer", "0180010401010200"),
    (
        "ipc export rows answer",
        "018080010501007f0180808080100102ffffffff0f030101de01c0a907",
    ),
    (
        "ipc export rows answer, tls",
        "0180800105000002ffffffff0f04010403c0a907",
    ),
    ("ipc refused", "01ffffffffffffffffff010600"),
    ("watchdog loop progress", "0000000134"),
    (
        "agent loop progress reply",
        "0000000b358080808080018080017f",
    ),
];

fn frames() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("execq configure", execq::encode(&configure()).unwrap()),
        ("execq scan", execq::encode(&scan()).unwrap()),
        ("execq result", execq::encode(&result()).unwrap()),
        ("execq ready", execq::encode(&ready()).unwrap()),
        ("execq refused", execq::encode(&refused()).unwrap()),
        (
            "execq config, rules",
            execq::encode_config(&config(Some(vec![0xa5; 130]))).unwrap(),
        ),
        (
            "execq config, none",
            execq::encode_config(&config(None)).unwrap(),
        ),
        (
            "admin net resolve",
            encode_frame(&resolved(Some("example.org"), Some(1_767_225_600))).unwrap(),
        ),
        (
            "admin net resolve, none",
            encode_frame(&resolved(None, None)).unwrap(),
        ),
        (
            "records today",
            postcard::to_allocvec(&records_today()).unwrap(),
        ),
        ("ipc hello", ipc::encode(&hello()).unwrap()),
        ("ipc ping", ipc::encode(&ping()).unwrap()),
        ("ipc pong", ipc::encode(&pong()).unwrap()),
        (
            "ipc export setup",
            ipc::encode(&export_setup(true)).unwrap(),
        ),
        (
            "ipc export setup, file only",
            ipc::encode(&export_setup(false)).unwrap(),
        ),
        ("ipc export rows", ipc::encode(&export_rows()).unwrap()),
        (
            "ipc export setup answer",
            ipc::encode(&setup_answer()).unwrap(),
        ),
        (
            "ipc export rows answer",
            ipc::encode(&rows_answer(SinkFault::Connect(111))).unwrap(),
        ),
        (
            "ipc export rows answer, tls",
            ipc::encode(&rows_answer(SinkFault::Tls(TlsFault::Other))).unwrap(),
        ),
        ("ipc refused", ipc::encode(&refusal()).unwrap()),
        (
            "watchdog loop progress",
            encode_frame(&AdminMessage::LoopProgress(LoopProgressRequest {})).unwrap(),
        ),
        (
            "agent loop progress reply",
            encode_frame(&AdminMessage::LoopProgressResponse(loop_progress())).unwrap(),
        ),
    ]
}

/// Named (lot 1.6, #613): every frame is the bytes postcard 1.1.3 wrote.
#[test]
fn our_frames_are_postcard_1_1_3_s_bytes() {
    let got = frames();
    let mut bad = Vec::new();
    for (name, bytes) in &got {
        let hex = hex::encode(bytes);
        match PINNED.iter().find(|(n, _)| n == name) {
            Some((_, want)) if *want == hex => {}
            Some((_, want)) => bad.push(format!("{name}: {hex}, pinned {want}")),
            None => bad.push(format!("{name}: {hex}, not pinned")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert_eq!(PINNED.len(), got.len(), "one pin per frame");
}

/// Named (lot 1.6, #613): each pinned frame decodes back to its value.
#[test]
fn our_frames_decode_to_their_values() {
    let bytes = |name: &str| {
        let (_, hex) = PINNED.iter().find(|(n, _)| *n == name).unwrap();
        hex::decode(hex).unwrap()
    };
    assert_eq!(
        execq::decode::<ToScanner>(&bytes("execq configure")).unwrap(),
        configure()
    );
    assert_eq!(
        execq::decode::<ToScanner>(&bytes("execq scan")).unwrap(),
        scan()
    );
    assert_eq!(
        execq::decode::<FromScanner>(&bytes("execq result")).unwrap(),
        result()
    );
    assert_eq!(
        execq::decode::<FromScanner>(&bytes("execq ready")).unwrap(),
        ready()
    );
    assert_eq!(
        execq::decode::<FromScanner>(&bytes("execq refused")).unwrap(),
        refused()
    );
    assert_eq!(
        execq::decode_config(&bytes("execq config, rules")).unwrap(),
        config(Some(vec![0xa5; 130]))
    );
    assert_eq!(
        execq::decode_config(&bytes("execq config, none")).unwrap(),
        config(None)
    );
    let frame = bytes("admin net resolve");
    assert_eq!(
        decode_frame(&frame).unwrap(),
        Some((
            resolved(Some("example.org"), Some(1_767_225_600)),
            frame.len()
        ))
    );
    let frame = bytes("admin net resolve, none");
    assert_eq!(
        decode_frame(&frame).unwrap(),
        Some((resolved(None, None), frame.len()))
    );
    assert_eq!(
        postcard::from_bytes::<RecordsToday>(&bytes("records today")).unwrap(),
        records_today()
    );
    // lot 1.8: the core ↔ export worker messages, read as each side reads
    // them (`ipc::decode`: the whole packet, no trailing byte)
    assert_eq!(
        ipc::decode::<FromWorker>(&bytes("ipc hello")).unwrap(),
        hello()
    );
    assert_eq!(ipc::decode::<ToWorker>(&bytes("ipc ping")).unwrap(), ping());
    assert_eq!(
        ipc::decode::<FromWorker>(&bytes("ipc pong")).unwrap(),
        pong()
    );
    assert_eq!(
        ipc::decode::<ToWorker>(&bytes("ipc export setup")).unwrap(),
        export_setup(true)
    );
    assert_eq!(
        ipc::decode::<ToWorker>(&bytes("ipc export setup, file only")).unwrap(),
        export_setup(false)
    );
    assert_eq!(
        ipc::decode::<ToWorker>(&bytes("ipc export rows")).unwrap(),
        export_rows()
    );
    assert_eq!(
        ipc::decode::<FromWorker>(&bytes("ipc export setup answer")).unwrap(),
        setup_answer()
    );
    assert_eq!(
        ipc::decode::<FromWorker>(&bytes("ipc export rows answer")).unwrap(),
        rows_answer(SinkFault::Connect(111))
    );
    assert_eq!(
        ipc::decode::<FromWorker>(&bytes("ipc export rows answer, tls")).unwrap(),
        rows_answer(SinkFault::Tls(TlsFault::Other))
    );
    assert_eq!(
        ipc::decode::<FromWorker>(&bytes("ipc refused")).unwrap(),
        refusal()
    );
    // the requests are within the protocol's bounds, as the core sends them
    for name in [
        "ipc export setup",
        "ipc export setup, file only",
        "ipc export rows",
    ] {
        let req = ipc::decode::<ToWorker>(&bytes(name)).unwrap().req;
        assert_eq!(req.check(), Ok(()), "{name}");
    }
    // the watchdog's exchange: its request, the agent's reply as the
    // watchdog reads it (`decode_loop_progress`, the 4-byte length off), and
    // an older agent's reply, its two fields only (lot 353's third missing)
    let frame = bytes("watchdog loop progress");
    assert_eq!(
        decode_frame(&frame).unwrap(),
        Some((
            AdminMessage::LoopProgress(LoopProgressRequest {}),
            frame.len()
        ))
    );
    let frame = bytes("agent loop progress reply");
    assert_eq!(
        decode_frame(&frame).unwrap(),
        Some((
            AdminMessage::LoopProgressResponse(loop_progress()),
            frame.len()
        ))
    );
    assert_eq!(decode_loop_progress(&frame[4..]).unwrap(), loop_progress());
    let older = &frame[4..frame.len() - 1];
    assert_eq!(
        decode_loop_progress(older).unwrap(),
        LoopProgressResponse {
            unsigned_ms: 0,
            ..loop_progress()
        }
    );
}
