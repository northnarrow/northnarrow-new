//! `nn-admin export` (lot 276; `docs/operator/EXPORT.md`): the export's
//! state (`status`, signed telemetry) and the receiver's check of what it
//! got (`verify`), off the agent's host, with the agent's public key only.
//!
//! `verify` reads OCSF records — the JSONL files' lines, or a syslog
//! receiver's messages (an RFC 5424 header before the record, optionally
//! its RFC 5425 length) — and checks each record's row: `raw_data` must be
//! a row signed by the agent's key (`nn_evidence::row_verify`) whose
//! `entry_hash` is the one `unmapped.northnarrow.row` names; then, chain by
//! chain, the rows in their order must link (each row's `prev_hash` the
//! row before it's `entry_hash`; across a rotation through the terminator
//! the first row of the next file carries). A record delivered twice (at
//! least once) is counted, not refused.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;

use ed25519_dalek::VerifyingKey;
use nn_evidence::row_verify::{verify_row, RowFault};
use serde::Serialize;

/// A row's place: its file and line.
pub type Place = (u64, u64);

/// Where a chain does not follow: the row before, the row at the break,
/// and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Break {
    pub after: Place,
    pub at: Place,
    pub why: String,
}

/// What one chain's records came to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChainReport {
    pub chain: String,
    pub rows: u64,
    pub records: u64,
    /// Records whose `metadata.uid` came before (delivered twice).
    pub duplicates: u64,
    pub first: Option<(u64, u64)>,
    pub last: Option<(u64, u64)>,
    /// Rows that link to the row before them (the first row seen has
    /// nothing to link to).
    pub linked: u64,
    /// Places where the rows do not follow.
    pub breaks: Vec<Break>,
    /// A rotation whose terminator no record carried (its archive evicted
    /// before the export read it): not checked.
    pub unlinked_rotations: u64,
}

/// What the whole input came to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub lines: u64,
    pub records: u64,
    /// Lines that are no record (not JSON, no `raw_data`, no row place).
    pub malformed: Vec<(u64, String)>,
    /// Records whose row does not verify: `(line, why)`.
    pub tampered: Vec<(u64, String)>,
    pub chains: Vec<ChainReport>,
}

impl Report {
    /// 0: every record verifies and every chain is continuous; 13: a
    /// record does not verify (TAMPERED, as `heartbeat watch`); 11: a
    /// chain does not follow (BROKEN); 2: lines that are no record, or no
    /// record at all (an empty capture proves nothing: lot 276's lab took
    /// one for an OK).
    pub fn exit_code(&self) -> u8 {
        if !self.tampered.is_empty() {
            13
        } else if self.chains.iter().any(|c| !c.breaks.is_empty()) {
            11
        } else if !self.malformed.is_empty() || self.records == 0 {
            2
        } else {
            0
        }
    }
}

#[derive(Debug, Clone)]
struct Row {
    entry: String,
    prev: String,
    rotate: Option<String>,
}

/// The record of a line: the JSONL file's as it is, a syslog message's
/// after its header (and an RFC 5425 length before it).
fn record_of(line: &str) -> &str {
    let mut l = line.trim();
    // `MSG-LEN SP` of RFC 5425, when a receiver kept the frames
    if let Some((len, rest)) = l.split_once(' ') {
        if !len.is_empty() && len.bytes().all(|b| b.is_ascii_digit()) && rest.starts_with('<') {
            l = rest;
        }
    }
    if l.starts_with('<') {
        // `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG`
        let mut rest = l;
        for _ in 0..7 {
            match rest.split_once(' ') {
                Some((_, r)) => rest = r,
                None => return "",
            }
        }
        return rest;
    }
    l
}

/// A record's `unmapped.northnarrow.row`.
struct RowRef {
    chain: String,
    file: u64,
    line: u64,
    entry_hash: Option<String>,
    rotate: Option<String>,
}

fn pos_of(v: &serde_json::Value) -> Option<RowRef> {
    let r = v.get("unmapped")?.get("northnarrow")?.get("row")?;
    Some(RowRef {
        chain: r.get("chain")?.as_str()?.to_string(),
        file: r.get("file")?.as_u64()?,
        line: r.get("line")?.as_u64()?,
        entry_hash: r
            .get("entry_hash")
            .and_then(|h| h.as_str())
            .map(str::to_string),
        rotate: r.get("rotate").and_then(|t| t.as_str()).map(str::to_string),
    })
}

/// Verify every record of `input` with the agent's key.
pub fn verify(input: impl BufRead, pk: &VerifyingKey) -> std::io::Result<Report> {
    let mut rep = Report::default();
    let mut rows: BTreeMap<String, BTreeMap<(u64, u64), Row>> = BTreeMap::new();
    let mut records: BTreeMap<String, u64> = BTreeMap::new();
    let mut dups: BTreeMap<String, u64> = BTreeMap::new();
    let mut uids: BTreeSet<String> = BTreeSet::new();
    for (i, line) in input.lines().enumerate() {
        let line = line?;
        let n = i as u64 + 1;
        if line.trim().is_empty() {
            continue;
        }
        rep.lines += 1;
        let text = record_of(&line);
        let v: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                rep.malformed.push((n, format!("not a JSON record: {e}")));
                continue;
            }
        };
        let (
            Some(raw),
            Some(RowRef {
                chain,
                file,
                line: l,
                entry_hash: named,
                rotate,
            }),
        ) = (v.get("raw_data").and_then(|r| r.as_str()), pos_of(&v))
        else {
            rep.malformed
                .push((n, "no raw_data, or no unmapped.northnarrow.row".to_string()));
            continue;
        };
        rep.records += 1;
        *records.entry(chain.clone()).or_default() += 1;
        // every record is checked, a duplicate too
        let seal = match verify_row(raw.as_bytes(), &chain, pk) {
            Ok(s) => s,
            Err(e) => {
                rep.tampered.push((n, format!("{chain} {file}/{l}: {e}")));
                continue;
            }
        };
        if named.as_deref().is_some_and(|h| h != seal.entry_hash) {
            rep.tampered.push((
                n,
                format!(
                    "{chain} {file}/{l}: its row's entry_hash is {}, the record names another",
                    seal.entry_hash
                ),
            ));
            continue;
        }
        let duplicate = v
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(|u| u.as_str())
            .is_some_and(|uid| !uids.insert(uid.to_string()));
        let held = rows.entry(chain.clone()).or_default();
        if let Some(before) = held.get(&(file, l)) {
            if before.entry != seal.entry_hash {
                rep.tampered.push((
                    n,
                    format!("{chain} {file}/{l}: two different rows at one place"),
                ));
                continue;
            }
            if duplicate {
                *dups.entry(chain.clone()).or_default() += 1;
            }
            continue;
        }
        held.insert(
            (file, l),
            Row {
                entry: seal.entry_hash,
                prev: seal.prev_hash,
                rotate,
            },
        );
    }
    for (chain, rs) in rows {
        let mut c = ChainReport {
            chain: chain.clone(),
            rows: rs.len() as u64,
            records: records.get(&chain).copied().unwrap_or(0),
            duplicates: dups.get(&chain).copied().unwrap_or(0),
            first: rs.keys().next().copied(),
            last: rs.keys().next_back().copied(),
            ..ChainReport::default()
        };
        let mut prev: Option<((u64, u64), &Row)> = None;
        for (&at, r) in &rs {
            if let Some((p, pr)) = prev {
                let why = if at.0 == p.0 && at.1 == p.1 + 1 {
                    (r.prev != pr.entry)
                        .then(|| "its prev_hash is not the row before's".to_string())
                } else if at.0 == p.0 + 1 && at.1 == 1 {
                    match &r.rotate {
                        None => {
                            c.unlinked_rotations += 1;
                            None
                        }
                        Some(t) => match verify_row(t.as_bytes(), &chain, pk) {
                            Ok(ts)
                                if ts.terminator
                                    && ts.prev_hash == pr.entry
                                    && r.prev == ts.entry_hash =>
                            {
                                None
                            }
                            Ok(_) => Some("the terminator does not link the two files".to_string()),
                            Err(RowFault::Signature) | Err(RowFault::Hash { .. }) => {
                                Some("the terminator does not verify".to_string())
                            }
                            Err(e) => Some(format!("the terminator: {e}")),
                        },
                    }
                } else if at.0 == p.0 {
                    Some(format!("{} row(s) missing", at.1 - p.1 - 1))
                } else {
                    Some("rows missing across files".to_string())
                };
                match why {
                    Some(why) => c.breaks.push(Break { after: p, at, why }),
                    None => c.linked += 1,
                }
            }
            prev = Some((at, r));
        }
        rep.chains.push(c);
    }
    Ok(rep)
}

/// The report as text: one line per chain, an `ALERT` line per problem
/// (at most 20 of each kind named), and the verdict.
pub fn report_lines(r: &Report) -> Vec<String> {
    let mut out = vec![format!(
        "export verify: {} record(s) in {} line(s), {} chain(s)",
        r.records,
        r.lines,
        r.chains.len()
    )];
    let at = |p: Option<(u64, u64)>| p.map_or("-".to_string(), |(f, l)| format!("{f}/{l}"));
    for c in &r.chains {
        out.push(format!(
            "  {}: {} row(s) {} … {}, {} record(s), {} duplicate(s), {} linked, {} break(s){}",
            c.chain,
            c.rows,
            at(c.first),
            at(c.last),
            c.records,
            c.duplicates,
            c.linked,
            c.breaks.len(),
            if c.unlinked_rotations > 0 {
                format!(
                    ", {} rotation(s) without their terminator",
                    c.unlinked_rotations
                )
            } else {
                String::new()
            }
        ));
    }
    for (n, why) in r.tampered.iter().take(20) {
        out.push(format!("ALERT TAMPERED line {n}: {why}"));
    }
    for c in &r.chains {
        for b in c.breaks.iter().take(20) {
            out.push(format!(
                "ALERT BROKEN {}: after {}/{} at {}/{}: {}",
                c.chain, b.after.0, b.after.1, b.at.0, b.at.1, b.why
            ));
        }
    }
    for (n, why) in r.malformed.iter().take(20) {
        out.push(format!("MALFORMED line {n}: {why}"));
    }
    out.push(match r.exit_code() {
        0 => "OK: every record's row is signed by the agent's key, every chain follows from its \
              first row seen"
            .to_string(),
        13 => "TAMPERED: a record's row is not signed by the agent's key".to_string(),
        11 => "BROKEN: a chain does not follow (rows missing or changed)".to_string(),
        _ if r.malformed.is_empty() => "EMPTY: no export record to verify".to_string(),
        _ => "MALFORMED: lines that are no export record".to_string(),
    });
    out
}

/// `export status`: the signed status's export field as lines.
pub fn status_lines(e: Option<&nn_proto::admin_protocol::ExportStatus>) -> Vec<String> {
    let Some(e) = e else {
        return vec![
            "export: none (no signed export.local; an agent older than lot 276 reports none \
             either)"
                .to_string(),
        ];
    };
    let mut out = vec![format!(
        "export: {}{}",
        e.state,
        e.why
            .as_ref()
            .map(|w| format!(" ({w})"))
            .unwrap_or_default()
    )];
    if let Some(c) = &e.config {
        out.push(format!("  config: {c}"));
    }
    if let Some(h) = &e.config_sha256 {
        out.push(format!("  config sha256: {h}"));
    }
    out.push(format!(
        "  ocsf {} · worker {} · port pinned {} · stage 8 lost {}",
        e.ocsf_version,
        e.worker,
        match e.port_pinned {
            Some(true) => "yes",
            Some(false) => "no",
            None => "-",
        },
        e.lost
    ));
    for k in &e.sinks {
        out.push(format!(
            "  sink {} {}: {}{} · {} row(s), {} record(s), {} unverified, {} fault(s), {} lost{}",
            k.sink,
            k.target,
            k.state,
            k.fault
                .as_ref()
                .map(|f| format!(" ({f})"))
                .unwrap_or_default(),
            k.rows,
            k.records,
            k.unverified,
            k.faults,
            k.lost,
            k.last_delivery
                .as_ref()
                .map(|t| format!(" · last {t}"))
                .unwrap_or_default()
        ));
        for c in &k.chains {
            out.push(format!(
                "    {}: cursor {} · {} in flight · {} byte(s) behind · {} lost",
                c.chain,
                c.cursor
                    .map_or("-".to_string(), |(f, l)| format!("{f}/{l}")),
                c.in_flight,
                c.behind_bytes,
                c.lost
            ));
        }
    }
    if let Some(t) = &e.cursors_saved {
        out.push(format!(
            "  cursors written {t} ({} time(s))",
            e.cursor_saves
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    /// A v3 data line of `chain` signed by `k`, linked to `prev`.
    fn row(k: &SigningKey, chain: &str, n: u64, prev: &str) -> String {
        let body = format!("{{\"n\":{n},\"fmt_ver\":3,\"prev_hash\":\"{prev}\"");
        sealed(k, chain, "data", prev, &body)
    }

    /// A v3 terminator of `chain`'s file 1, linked to `prev`.
    fn terminator(k: &SigningKey, chain: &str, prev: &str) -> String {
        let body = format!(
            "{{\"rotate\":{{\"fmt_ver\":3,\"this_seq\":1,\"next_seq\":2,\"record_count\":2,\
             \"bytes\":100}},\"ts\":\"2026-11-03T00:00:00.000000Z\",\"prev_hash\":\"{prev}\""
        );
        sealed(k, chain, "terminator", prev, &body)
    }

    fn sealed(k: &SigningKey, chain: &str, role: &str, prev: &str, body: &str) -> String {
        let pre = format!("{body},\"entry_hash\":\"\",\"agent_sig\":\"\"}}");
        let mut h = Sha256::new();
        h.update(format!("northnarrow/chainlog/{chain}/{role}/v3\0").as_bytes());
        h.update(hex::decode(prev).unwrap());
        h.update(pre.as_bytes());
        let d: [u8; 32] = h.finalize().into();
        let sig = base64::engine::general_purpose::STANDARD.encode(k.sign(&d).to_bytes());
        format!(
            "{body},\"entry_hash\":\"{}\",\"agent_sig\":\"{sig}\"}}",
            hex::encode(d)
        )
    }

    fn record(chain: &str, file: u64, line: u64, raw: &str, uid: &str) -> String {
        let entry = nn_evidence::row_verify::links(raw.as_bytes()).unwrap().1;
        serde_json::json!({
            "class_uid": 2004,
            "metadata": {"uid": uid},
            "raw_data": raw,
            "unmapped": {"northnarrow": {"row": {
                "chain": chain, "file": file, "line": line, "entry_hash": entry
            }}}
        })
        .to_string()
    }

    fn chain_of(k: &SigningKey, n: u64) -> Vec<String> {
        let mut prev = "0".repeat(64);
        (1..=n)
            .map(|i| {
                let r = row(k, "detections", i, &prev);
                prev = nn_evidence::row_verify::links(r.as_bytes()).unwrap().1;
                r
            })
            .collect()
    }

    #[test]
    fn a_continuous_chain_verifies_and_duplicates_are_counted() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let rows = chain_of(&k, 5);
        let mut input: Vec<String> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| record("detections", 1, i as u64 + 1, r, &format!("u{i}")))
            .collect();
        // at least once: one delivered twice; one as a syslog message
        input.push(input[2].clone());
        input[4] = format!(
            "123 <107>1 2026-11-03T00:00:00.000Z host northnarrow - detection_finding - {}",
            input[4]
        );
        let r = verify(input.join("\n").as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 0, "{:#?}", r);
        assert_eq!(r.chains[0].rows, 5);
        assert_eq!(r.chains[0].linked, 4);
        assert_eq!(r.chains[0].duplicates, 1);
        assert!(report_lines(&r).last().unwrap().starts_with("OK"));
    }

    #[test]
    fn a_gap_a_forgery_and_a_stranger_s_key_are_named() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let rows = chain_of(&k, 5);
        let rec = |i: usize| record("detections", 1, i as u64 + 1, &rows[i], &format!("u{i}"));
        // row 3 missing: BROKEN
        let r = verify(
            [rec(0), rec(1), rec(3), rec(4)].join("\n").as_bytes(),
            &k.verifying_key(),
        )
        .unwrap();
        assert_eq!(r.exit_code(), 11);
        assert_eq!(r.chains[0].breaks[0].why, "1 row(s) missing");
        // a changed byte: TAMPERED
        let bent = rows[1].replace("\"n\":2", "\"n\":9");
        let r = verify(
            [rec(0), record("detections", 1, 2, &bent, "x")]
                .join("\n")
                .as_bytes(),
            &k.verifying_key(),
        )
        .unwrap();
        assert_eq!(r.exit_code(), 13);
        // another key's rows
        let other = SigningKey::from_bytes(&[6; 32]);
        let r = verify(rec(0).as_bytes(), &other.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 13);
        // a record that names another hash than its row's
        let mut v: serde_json::Value = serde_json::from_str(&rec(0)).unwrap();
        v["unmapped"]["northnarrow"]["row"]["entry_hash"] = "a".repeat(64).into();
        let r = verify(v.to_string().as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 13);
        // a line that is no record
        let r = verify(b"hello\n{\"x\":1}".as_slice(), &k.verifying_key()).unwrap();
        assert_eq!((r.exit_code(), r.malformed.len()), (2, 2));
        // no record at all: nothing verified, never an OK
        for empty in [&b""[..], b"\n\n"] {
            let r = verify(empty, &k.verifying_key()).unwrap();
            assert_eq!(r.exit_code(), 2);
            assert!(report_lines(&r).last().unwrap().starts_with("EMPTY"));
        }
    }

    fn hash(raw: &str) -> String {
        nn_evidence::row_verify::links(raw.as_bytes()).unwrap().1
    }

    /// Two genuine rows that do not follow, two rows at one place: named.
    #[test]
    fn rows_that_do_not_follow_or_share_a_place_are_named() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let rows = chain_of(&k, 2);
        // a genuine row at line 2 that is not the one after line 1
        let stray = row(&k, "detections", 9, &"f".repeat(64));
        let r = verify(
            [
                record("detections", 1, 1, &rows[0], "a"),
                record("detections", 1, 2, &stray, "b"),
            ]
            .join("\n")
            .as_bytes(),
            &k.verifying_key(),
        )
        .unwrap();
        assert_eq!(r.exit_code(), 11, "{r:#?}");
        assert_eq!(
            r.chains[0].breaks[0].why,
            "its prev_hash is not the row before's"
        );
        // two different genuine rows claimed at one place
        let r = verify(
            [
                record("detections", 1, 1, &rows[0], "a"),
                record("detections", 1, 1, &rows[1], "b"),
            ]
            .join("\n")
            .as_bytes(),
            &k.verifying_key(),
        )
        .unwrap();
        assert_eq!(r.exit_code(), 13, "{r:#?}");
        assert!(r.tampered[0].1.contains("two different rows at one place"));
    }

    /// Across a rotation the terminator links the files: the last row of
    /// one to the terminator, the terminator to the next file's first row.
    #[test]
    fn a_rotation_is_linked_by_its_terminator() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let rows = chain_of(&k, 2);
        let t = terminator(&k, "detections", &hash(&rows[1]));
        let next = row(&k, "detections", 3, &hash(&t));
        let with_next = |t: Option<&str>, next: &str| {
            let mut v: serde_json::Value =
                serde_json::from_str(&record("detections", 2, 1, next, "c")).unwrap();
            if let Some(t) = t {
                v["unmapped"]["northnarrow"]["row"]["rotate"] = t.into();
            }
            [
                record("detections", 1, 1, &rows[0], "a"),
                record("detections", 1, 2, &rows[1], "b"),
                v.to_string(),
            ]
            .join("\n")
        };
        let with = |t: Option<&str>| with_next(t, &next);
        let r = verify(with(Some(&t)).as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 0, "{r:#?}");
        assert_eq!((r.chains[0].linked, r.chains[0].unlinked_rotations), (2, 0));
        // without its terminator: counted, not a break
        let r = verify(with(None).as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 0, "{r:#?}");
        assert_eq!(r.chains[0].unlinked_rotations, 1);
        // a genuine terminator of another place: it does not link the files
        let elsewhere = terminator(&k, "detections", &hash(&rows[0]));
        let r = verify(with(Some(&elsewhere)).as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 11, "{r:#?}");
        assert_eq!(
            r.chains[0].breaks[0].why,
            "the terminator does not link the two files"
        );
        // the next file's first row follows its terminator, the terminator
        // does not follow the last row before it
        let next2 = row(&k, "detections", 3, &hash(&elsewhere));
        let r = verify(
            with_next(Some(&elsewhere), &next2).as_bytes(),
            &k.verifying_key(),
        )
        .unwrap();
        assert_eq!(
            r.chains[0].breaks[0].why,
            "the terminator does not link the two files"
        );
        // a data row in the terminator's place
        let r = verify(with(Some(&rows[1])).as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.exit_code(), 11, "{r:#?}");
        // a terminator signed by another key
        let other = SigningKey::from_bytes(&[6; 32]);
        let forged = terminator(&other, "detections", &hash(&rows[1]));
        let r = verify(with(Some(&forged)).as_bytes(), &k.verifying_key()).unwrap();
        assert_eq!(r.chains[0].breaks[0].why, "the terminator does not verify");
    }

    #[test]
    fn the_status_is_said_in_lines() {
        assert!(status_lines(None)[0].starts_with("export: none"));
        let e = nn_proto::admin_protocol::ExportStatus {
            state: "on".into(),
            why: None,
            config: Some("on · chains detections · start end · file".into()),
            config_sha256: Some("ab".repeat(32)),
            ocsf_version: "1.9.0".into(),
            worker: "ready".into(),
            port_pinned: Some(true),
            sinks: vec![nn_proto::admin_protocol::ExportSinkStatus {
                sink: "syslog".into(),
                target: "127.0.0.1:6514 (receiver.lab)".into(),
                state: "down".into(),
                fault: Some("connect: Connection refused".into()),
                rows: 3,
                records: 4,
                unverified: 0,
                faults: 2,
                lost: 0,
                last_delivery: None,
                chains: vec![nn_proto::admin_protocol::ExportChainStatus {
                    chain: "detections".into(),
                    cursor: Some((2, 7)),
                    in_flight: 1,
                    behind_bytes: 900,
                    lost: 0,
                }],
            }],
            lost: 0,
            cursors_saved: None,
            cursor_saves: 0,
        };
        let l = status_lines(Some(&e)).join("\n");
        for want in [
            "export: on",
            "port pinned yes",
            "sink syslog 127.0.0.1:6514 (receiver.lab): down (connect: Connection refused)",
            "detections: cursor 2/7 · 1 in flight · 900 byte(s) behind",
        ] {
            assert!(l.contains(want), "{want}:\n{l}");
        }
    }
}
