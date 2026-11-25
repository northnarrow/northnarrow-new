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

use nn_proto::admin_protocol::{
    AdminMessage, AdminResult, NetResolveResponse, RecordsToday, decode_frame, encode_frame,
};
use nn_proto::execq::{
    self, FromScanner, HashEntry, Reason, ScanConfig, ScanRequest, ScanResult, ScanVerdict,
    ScannerHello, ToScanner,
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
}
