//! Lot 1.6 (F11): chrono → jiff with every time's text kept, proven on what
//! chrono itself wrote and read.
//!
//! `tests/data/time-chrono-0.4.45.jsonl` was written by chrono 0.4.45, the
//! version the workspace locked before this lot, one JSON object per line:
//!
//! - `fmt`: the time `secs`, `nanos` (`DateTime::from_timestamp`) as the
//!   chains stamp it, `micros` (`format("%Y-%m-%dT%H:%M:%S%.6fZ")`); to the
//!   second, `secs_z` (`format("%Y-%m-%dT%H:%M:%SZ")`, which chrono's
//!   `to_rfc3339_opts(SecondsFormat::Secs, true)` equalled on every row);
//!   `rfc3339` (`to_rfc3339()`); its UTC day, `date`
//!   (`date_naive().format("%Y-%m-%d")`);
//! - `unix`: `secs` and `text`, `Utc.timestamp_opt(secs, 0)` formatted
//!   `%Y-%m-%dT%H:%M:%S` (null where chrono had no such time);
//! - `parse`: `in` and what `DateTime::parse_from_rfc3339` made of it —
//!   `secs` (`timestamp()`), `nanos` (`timestamp_subsec_nanos()`), `micros`
//!   (the chains' format of it, in UTC) — all null where it refused;
//! - `diff`: `a`, `b` and `secs`, `(a - b).num_seconds()` of the two read
//!   as UTC (the heartbeat verifier's arithmetic).
//!
//! The times: the epoch and the second around it, 2038 and 2106, leap days
//! (2000, 2004, 2100), the end of a day, 2262 (Linux's last clock time), the
//! years 0 and 9999 and the ends of jiff's range, sub-second times on every
//! digit boundary, and seeded pseudo-random ones; the texts read: chrono's
//! own outputs and their variants (`t`, `z`, a space, offsets up to ±23:59,
//! U+2212, one to twenty fractional digits, leap seconds anywhere in a
//! minute's last second, 9999-12-31 with offsets) and refused ones (offsets
//! without a colon or out of range, a missing second, annotations, ISO 8601
//! basic form, impossible days, stray bytes), plus seeded mutations.
//!
//! The round trip below covers what the corpus does not list: every
//! format read back gives the time written, on seeded random times over
//! jiff's whole range.

use nn_evidence::time::{
    Rfc3339, SignedDuration, Timestamp, format_date, format_micros, format_rfc3339_offset,
    format_secs, format_unix_date_time, parse_rfc3339, parse_timestamp, utc,
};
use serde_json::Value;

const CORPUS: &str = include_str!("data/time-chrono-0.4.45.jsonl");

fn rows(kind: &str) -> Vec<Value> {
    CORPUS
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).expect("a JSON line"))
        .filter(|v| v["k"] == kind)
        .collect()
}

fn ts(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::from_nanosecond(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
        .expect("a time in jiff's range")
}

fn text(v: &Value) -> &str {
    v.as_str().expect("a string")
}

/// Named (lot 1.6): each format writes chrono's bytes.
#[test]
fn every_format_writes_chronos_text() {
    let fmt = rows("fmt");
    assert!(fmt.len() >= 300, "{} rows", fmt.len());
    for r in &fmt {
        let (secs, nanos) = (r["secs"].as_i64().unwrap(), r["nanos"].as_u64().unwrap());
        let t = ts(secs, u32::try_from(nanos).unwrap());
        assert_eq!(format_micros(t), text(&r["micros"]), "{r}");
        assert_eq!(format_secs(t), text(&r["secs_z"]), "{r}");
        assert_eq!(format_rfc3339_offset(t), text(&r["rfc3339"]), "{r}");
        assert_eq!(format_date(utc(t).date()), text(&r["date"]), "{r}");
        assert_eq!(Rfc3339::from(t).format_micros(), text(&r["micros"]), "{r}");
    }
}

/// Named (lot 1.6): a Unix time to the second is chrono's text wherever
/// chrono had one; beyond its ±262143 years, a year of more digits.
#[test]
fn unix_times_are_chronos_text() {
    let unix = rows("unix");
    assert!(unix.len() >= 40, "{} rows", unix.len());
    for r in &unix {
        let secs = r["secs"].as_i64().unwrap();
        let ours = format_unix_date_time(secs);
        match r["text"].as_str() {
            Some(chrono) => assert_eq!(ours, chrono, "{r}"),
            None => {
                // a year of six digits or more, after its sign
                let year = ours[1..].split('-').next().unwrap();
                assert!(
                    ours.starts_with(['+', '-']) && year.len() >= 6,
                    "{r}: {ours}"
                );
            }
        }
    }
}

/// Named (lot 1.6): RFC 3339 is read as chrono read it — the same texts
/// refused, the same seconds and nanoseconds (a leap second's too), the
/// same time written back.
#[test]
fn rfc3339_is_read_as_chrono_read_it() {
    let parse = rows("parse");
    let read: Vec<&Value> = parse.iter().filter(|r| !r["secs"].is_null()).collect();
    assert!(read.len() >= 100 && parse.len() - read.len() >= 300);
    assert!(
        read.iter()
            .any(|r| r["nanos"].as_u64().unwrap() >= 1_000_000_000)
    );
    for r in &parse {
        let input = text(&r["in"]);
        match parse_rfc3339(input) {
            None => assert!(r["secs"].is_null(), "refused {input:?}: {r}"),
            Some(t) => {
                assert_eq!(Some(t.unix_seconds()), r["secs"].as_i64(), "{r}");
                assert_eq!(
                    Some(u64::from(t.subsec_nanos())),
                    r["nanos"].as_u64(),
                    "{r}"
                );
                assert_eq!(t.format_micros(), text(&r["micros"]), "{r}");
            }
        }
    }
}

/// Named (lot 1.6): the whole seconds between two times read are chrono's,
/// leap seconds and times before the epoch included.
#[test]
fn seconds_between_are_chronos() {
    let diff = rows("diff");
    assert!(diff.len() >= 200, "{} rows", diff.len());
    for r in &diff {
        let a = parse_rfc3339(text(&r["a"])).unwrap();
        let b = parse_rfc3339(text(&r["b"])).unwrap();
        assert_eq!(Some(a.whole_seconds_since(b)), r["secs"].as_i64(), "{r}");
        // chrono's order agreed with its differences
        let d = a.whole_seconds_since(b);
        if d > 0 {
            assert!(a > b, "{r}");
        } else if d < 0 {
            assert!(a < b, "{r}");
        }
    }
}

/// splitmix64: seeded, the same times every run.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Named (lot 1.6): every text read back gives the time written — to the
/// nanosecond, the microsecond or the second its format keeps — from year 0
/// (RFC 3339's first) to the end of jiff's range.
#[test]
fn every_format_reads_back_to_its_time() {
    let lo: i128 = -62_167_219_200; // 0000-01-01T00:00:00Z
    let hi = i128::from(Timestamp::MAX.as_second());
    let mut rng = Seeded(0x16);
    for i in 0..50_000u32 {
        let span = u64::try_from(hi - lo).unwrap();
        let secs = if i % 2 == 0 {
            lo + i128::from(rng.next() % span)
        } else {
            i128::from(rng.next() % 8_000_000_000)
        };
        let nanos = match i % 4 {
            0 => 0,
            1 => (rng.next() % 1_000) * 1_000_000,
            2 => (rng.next() % 1_000_000) * 1_000,
            _ => rng.next() % 1_000_000_000,
        };
        let t = Timestamp::from_nanosecond(secs * 1_000_000_000 + i128::from(nanos)).unwrap();
        let exact = parse_rfc3339(&format_rfc3339_offset(t)).unwrap();
        assert_eq!(exact, Rfc3339::from(t), "{t}");
        assert_eq!(exact.to_timestamp(), Some(t), "{t}");
        let micros = parse_timestamp(&format_micros(t)).unwrap();
        assert!(
            t.duration_since(micros) < SignedDuration::from_micros(1),
            "{t}"
        );
        assert!(micros <= t, "{t}");
        let second = parse_rfc3339(&format_secs(t)).unwrap();
        assert_eq!(
            second.unix_seconds(),
            t.as_second() - i64::from(t.subsec_nanosecond() < 0),
            "{t}"
        );
        assert_eq!(second.subsec_nanos(), 0, "{t}");
    }
}
