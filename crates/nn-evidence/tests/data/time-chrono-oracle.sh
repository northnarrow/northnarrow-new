#!/usr/bin/env bash
# The chrono oracle of tests/time_chrono_corpus.rs (lot 1.8, the review of
# #615): chrono 0.4.45 itself, the version the workspace locked before lot
# 1.6 moved the time's text to jiff behind nn_evidence::time.
#
#   time-chrono-oracle.sh regen [--write]
#       chrono recomputes every output of time-chrono-0.4.45.jsonl from the
#       inputs the file lists (each `fmt` row's time, `unix` row's seconds,
#       `parse` row's text, `diff` row's two texts) and writes the corpus
#       again, one JSON object per line, its keys sorted. It must come out
#       byte for byte the committed file (exit 1 otherwise, with the diff);
#       `--write` replaces the file instead: to add a case, append its row
#       with its inputs alone (`{"k":"parse","in":"…"}`) and regenerate.
#   time-chrono-oracle.sh compare [N] [SEED]
#       nn_evidence::time against chrono on N seeded pseudo-random cases
#       (default 2000000, at most 100000000; SEED default 0x16, splitmix64,
#       the same cases every run): every writer on N times over jiff's
#       range, Unix text on N seconds over all of i64, N/2 texts read
#       (chrono's outputs and their seeded mutations), N/5 differences.
#       Exit 1 on any mismatch, with the first ones.
#
# Why a script and not a workspace test: chrono 0.4 is unmaintained
# (RUSTSEC-2026-0543) and is in no manifest, lockfile or source of the
# repository (xtask/tests/time_text.rs). The oracle builds in a temporary
# crate outside the workspace — chrono pinned exactly, nn-evidence by path,
# the workspace's Cargo.lock as its starting lock — which is removed after
# the run. The corpus test is the CI's proof; run this when
# nn_evidence::time changes, or to extend the corpus. Needs cargo and the
# registry (or network) for chrono 0.4.45.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
corpus=$here/time-chrono-0.4.45.jsonl
toolchain=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$repo/rust-toolchain.toml")

mode=${1:-}
case "$mode" in
regen)
    write=0
    [ "${2:-}" = "--write" ] && write=1
    ;;
compare)
    n=${2:-2000000}
    seed=${3:-0x16}
    case "$n" in '' | *[!0-9]*) echo "compare: N is a number" >&2; exit 2 ;; esac
    [ "$n" -ge 1 ] && [ "$n" -le 100000000 ] || { echo "compare: N in 1..=100000000" >&2; exit 2; }
    ;;
*)
    sed -n '2,20s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 2
    ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/src"
cp "$repo/Cargo.lock" "$work/Cargo.lock"
cat >"$work/Cargo.toml" <<EOF
[package]
name = "nn-time-chrono-oracle"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
chrono = { version = "=0.4.45", default-features = false, features = ["std"] }
serde_json = "1"
nn-evidence = { path = "$repo/crates/nn-evidence" }
EOF

cat >"$work/src/main.rs" <<'EOF'
use std::io::Write;

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use nn_evidence::time::{
    format_date, format_micros, format_rfc3339_offset, format_secs, format_unix_date_time,
    parse_rfc3339, utc, Rfc3339, Timestamp,
};
use serde_json::{json, Value};

const MICROS: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";
const SECS_Z: &str = "%Y-%m-%dT%H:%M:%SZ";

fn fmt_row(secs: i64, nanos: u32) -> Value {
    let t = DateTime::from_timestamp(secs, nanos).expect("a time chrono has");
    let secs_z = t.format(SECS_Z).to_string();
    assert_eq!(
        secs_z,
        t.to_rfc3339_opts(SecondsFormat::Secs, true),
        "secs_z is chrono's to_rfc3339_opts(Secs, true)"
    );
    json!({
        "k": "fmt", "secs": secs, "nanos": nanos,
        "micros": t.format(MICROS).to_string(), "secs_z": secs_z,
        "rfc3339": t.to_rfc3339(), "date": t.date_naive().format("%Y-%m-%d").to_string(),
    })
}

fn unix_text(secs: i64) -> Option<String> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string())
}

fn parse_row(input: &str) -> Value {
    match DateTime::parse_from_rfc3339(input) {
        Ok(t) => json!({
            "k": "parse", "in": input, "secs": t.timestamp(),
            "nanos": t.timestamp_subsec_nanos(),
            "micros": t.with_timezone(&Utc).format(MICROS).to_string(),
        }),
        Err(_) => json!({"k": "parse", "in": input, "secs": null, "nanos": null, "micros": null}),
    }
}

fn read_utc(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

fn diff_row(a: &str, b: &str) -> Value {
    let (ta, tb) = (read_utc(a).expect("a text chrono reads"), read_utc(b).expect("a text chrono reads"));
    json!({"k": "diff", "a": a, "b": b, "secs": (ta - tb).num_seconds()})
}

fn regen(corpus: &str) -> String {
    let mut out = String::new();
    for (i, line) in corpus.lines().enumerate() {
        let r: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {e}", i + 1));
        let s = |k: &str| r[k].as_str().unwrap_or_else(|| panic!("line {}: no `{k}`", i + 1));
        let n = |k: &str| r[k].as_i64().unwrap_or_else(|| panic!("line {}: no `{k}`", i + 1));
        let row = match s("k") {
            "fmt" => fmt_row(n("secs"), u32::try_from(n("nanos")).expect("nanos")),
            "unix" => json!({"k": "unix", "secs": n("secs"), "text": unix_text(n("secs"))}),
            "parse" => parse_row(s("in")),
            "diff" => diff_row(s("a"), s("b")),
            k => panic!("line {}: kind {k:?}", i + 1),
        };
        out.push_str(&serde_json::to_string(&row).expect("JSON"));
        out.push('\n');
    }
    out
}

/// splitmix64, as the corpus test's round trip.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Default)]
struct Tally {
    checked: [u64; 4],
    accepted: u64,
    bad: Vec<String>,
    bad_count: u64,
}

impl Tally {
    fn check(&mut self, kind: usize, ok: bool, what: impl FnOnce() -> String) {
        self.checked[kind] += 1;
        if !ok {
            self.bad_count += 1;
            if self.bad.len() < 20 {
                self.bad.push(what());
            }
        }
    }
}

/// A text chrono or our reader may meet: chrono's own outputs, then a
/// seeded mutation of one of its characters.
const ALPHABET: &[char] = &[
    '0', '1', '2', '5', '6', '9', '-', '+', ':', '.', ',', 'T', 't', 'Z', 'z', ' ', '_', '\u{2212}',
    'x', '\0',
];

fn mutate(rng: &mut Seeded, s: &str) -> String {
    let mut c: Vec<char> = s.chars().collect();
    for _ in 0..=rng.below(2) {
        let at = rng.below(c.len() as u64 + 1) as usize;
        let ch = ALPHABET[rng.below(ALPHABET.len() as u64) as usize];
        match rng.below(3) {
            0 if at < c.len() => c[at] = ch,
            1 if at < c.len() => {
                c.remove(at);
            }
            _ => c.insert(at, ch),
        }
    }
    c.into_iter().collect()
}

fn compare(n: u64, seed: u64) -> Tally {
    let mut t = Tally::default();
    let mut rng = Seeded(seed);
    let lo = Timestamp::MIN.as_second();
    let hi = Timestamp::MAX.as_second();
    let span = (hi - lo) as u64;
    let mut texts: Vec<String> = Vec::new();
    // every writer, on times over jiff's range (chrono's is wider)
    for i in 0..n {
        let secs = if i % 2 == 0 {
            lo + rng.below(span) as i64
        } else {
            rng.below(8_000_000_000) as i64 - 4_000_000_000
        };
        let nanos = match i % 4 {
            0 => 0,
            1 => rng.below(1_000) * 1_000_000,
            2 => rng.below(1_000_000) * 1_000,
            _ => rng.below(1_000_000_000),
        } as u32;
        let c = DateTime::from_timestamp(secs, nanos).expect("in chrono's range");
        let ns = i128::from(secs) * 1_000_000_000 + i128::from(nanos);
        let Ok(j) = Timestamp::from_nanosecond(ns) else {
            continue; // past jiff's last nanosecond
        };
        let micros = c.format(MICROS).to_string();
        t.check(0, format_micros(j) == micros, || format!("format_micros {secs}.{nanos:09}: {micros}"));
        t.check(0, Rfc3339::from(j).format_micros() == micros, || format!("Rfc3339::format_micros {secs}.{nanos:09}"));
        let secs_z = c.format(SECS_Z).to_string();
        t.check(0, format_secs(j) == secs_z, || format!("format_secs {secs}: {secs_z}"));
        let rfc = c.to_rfc3339();
        t.check(0, format_rfc3339_offset(j) == rfc, || format!("format_rfc3339_offset {secs}.{nanos:09}: {rfc}"));
        let date = c.date_naive().format("%Y-%m-%d").to_string();
        t.check(0, format_date(utc(j).date()) == date, || format!("format_date {secs}: {date}"));
        if i % 4 == 3 && texts.len() < 4096 {
            texts.extend([rfc, micros, secs_z]);
        }
    }
    // a Unix time to the second, over all of i64
    for i in 0..n {
        let secs = match i % 3 {
            0 => rng.next() as i64,
            1 => rng.below(1 << 44) as i64 - (1 << 43),
            _ => rng.below(1 << 36) as i64 - (1 << 35),
        };
        let ours = format_unix_date_time(secs);
        match unix_text(secs) {
            Some(c) => t.check(1, ours == c, || format!("format_unix_date_time {secs}: {ours}, chrono {c}")),
            None => {
                let year = ours[1..].split('-').next().unwrap_or("");
                t.check(1, ours.starts_with(['+', '-']) && year.len() >= 6, || {
                    format!("format_unix_date_time {secs} (none in chrono): {ours}")
                })
            }
        }
    }
    // texts read: chrono's outputs and their mutations
    let mut read: Vec<String> = Vec::new();
    for _ in 0..if texts.is_empty() { 0 } else { n / 2 } {
        let base = &texts[rng.below(texts.len() as u64) as usize];
        let s = if rng.below(4) == 0 { base.clone() } else { mutate(&mut rng, base) };
        let c = DateTime::parse_from_rfc3339(&s).ok();
        let ours = parse_rfc3339(&s);
        let same = match (c, ours) {
            (None, None) => true,
            (Some(c), Some(o)) => {
                o.unix_seconds() == c.timestamp()
                    && o.subsec_nanos() == c.timestamp_subsec_nanos()
                    && o.format_micros() == c.with_timezone(&Utc).format(MICROS).to_string()
            }
            _ => false,
        };
        t.check(2, same, || format!("parse_rfc3339 {s:?}: chrono {c:?}, ours {ours:?}"));
        if c.is_some() {
            t.accepted += 1;
            if read.len() < 8192 {
                read.push(s);
            }
        }
    }
    // the whole seconds between two texts read
    if !read.is_empty() {
        for _ in 0..n / 5 {
            let a = &read[rng.below(read.len() as u64) as usize];
            let b = &read[rng.below(read.len() as u64) as usize];
            let c = (read_utc(a).unwrap() - read_utc(b).unwrap()).num_seconds();
            let ours = match (parse_rfc3339(a), parse_rfc3339(b)) {
                (Some(x), Some(y)) => Some(x.whole_seconds_since(y)),
                _ => None,
            };
            t.check(3, ours == Some(c), || format!("whole_seconds_since {a:?} {b:?}: {ours:?}, chrono {c}"));
        }
    }
    t
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("regen") => {
            let corpus = std::fs::read_to_string(&args[2]).expect("the corpus");
            std::io::stdout().write_all(regen(&corpus).as_bytes()).expect("stdout");
        }
        Some("compare") => {
            let n: u64 = args[2].parse().expect("N");
            let seed = u64::from_str_radix(args[3].trim_start_matches("0x"), if args[3].starts_with("0x") { 16 } else { 10 })
                .expect("SEED");
            let t = compare(n, seed);
            println!(
                "compare: N={n} seed={:#x}: {} writer checks, {} Unix texts, {} texts read ({} accepted by chrono), {} differences; {} mismatches",
                seed, t.checked[0], t.checked[1], t.checked[2], t.accepted, t.checked[3], t.bad_count
            );
            for b in &t.bad {
                println!("  {b}");
            }
            std::process::exit(i32::from(t.bad_count > 0));
        }
        _ => {
            eprintln!("usage: oracle regen <corpus> | compare <n> <seed>");
            std::process::exit(2);
        }
    }
}
EOF

run() {
    RUSTUP_TOOLCHAIN=$toolchain CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$work/target} \
        cargo run --quiet --release --manifest-path "$work/Cargo.toml" -- "$@"
}

case "$mode" in
regen)
    run regen "$corpus" >"$work/corpus.jsonl"
    if [ "$write" = 1 ]; then
        cp "$work/corpus.jsonl" "$corpus"
        echo "regen: $(wc -l <"$corpus") rows written to $corpus"
    elif cmp -s "$work/corpus.jsonl" "$corpus"; then
        echo "regen: chrono 0.4.45 writes the corpus again, byte for byte ($(wc -l <"$corpus") rows)"
    else
        echo "regen: chrono's corpus differs from the committed one:" >&2
        diff "$corpus" "$work/corpus.jsonl" | head -40 >&2 || true
        exit 1
    fi
    ;;
compare)
    run compare "$n" "$seed"
    ;;
esac
