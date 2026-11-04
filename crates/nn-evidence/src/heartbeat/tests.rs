//! R12c-2 (lab PR 270): the external verifier's checks on a real signed
//! chain — each alert it must raise, and the quiet it must keep.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;

use super::*;
use crate::chain_host::testing::TestKey;
use crate::chain_host::ChainSigner;
use crate::chainlog::{NoProtection, RotatingChainLog, RotationConfig};

const T0: &str = "2026-11-01T10:00:00.000000Z";

fn at(s: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(T0)
        .unwrap()
        .with_timezone(&Utc)
        + Duration::seconds(s)
}

fn beat(seq: u64, s: i64) -> HeartbeatRecord {
    HeartbeatRecord {
        kind: if seq == 1 {
            BeatKind::Start
        } else {
            BeatKind::Beat
        },
        seq,
        ts: crate::audit::format_ts(at(s)),
        agent_id: "0011".into(),
        run: "aaaaaaaaaaaaaaaa".into(),
        boot_id: "b007".into(),
        uptime_ms: (s as u64) * 1000,
        interval_secs: 30,
        version: "0.0.1".into(),
        posture: "observing".into(),
        combat_stage: None,
        trust_level: Some("L3".into()),
        degradations: Vec::new(),
        decision_rounds: seq * 60,
        decision_since_last_ms: 400,
        loss: vec![Some(0); 7],
        actions: BeatActions::default(),
        probe_gaps: Some(0),
        heads: vec![BeatHead {
            chain: "audit".into(),
            seq: Some(100 + seq),
            hash: format!("{:064x}", 100 + seq),
            ..BeatHead::default()
        }],
        stop_reason: None,
        capabilities: None,
        nodns: None,
    }
}

/// A beat carrying a capability manifest of hash `h` (R13).
fn beat_m(seq: u64, s: i64, h: &str, revision: u64, settled: bool) -> HeartbeatRecord {
    let mut b = beat(seq, s);
    b.capabilities = Some(BeatManifest {
        hash: h.repeat(64 / h.len()),
        revision,
        settled,
        contract: Some("c1".repeat(32)),
        contract_version: Some(1),
        kernel: Some("6.8.0-147-generic".into()),
    });
    b
}

/// A chain of beats on disk, and its lines.
struct Chain {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    log: RotatingChainLog<HeartbeatRecord, TestKey>,
    pk: VerifyingKey,
}

impl Chain {
    fn new() -> Self {
        Self::keyed(None)
    }

    /// Another chain signed with `other`'s key (a chain rebuilt by whoever
    /// holds the key).
    fn sharing_key(other: &Chain) -> Self {
        Self::keyed(Some(other._dir.path().join("k")))
    }

    fn keyed(key_path: Option<std::path::PathBuf>) -> Self {
        Self::keyed_capped(key_path, u64::MAX)
    }

    /// A chain that rotates past `cap` bytes.
    fn capped(cap: u64) -> Self {
        Self::keyed_capped(None, cap)
    }

    fn keyed_capped(key_path: Option<std::path::PathBuf>, cap: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat.jsonl");
        let key_path = key_path.unwrap_or_else(|| dir.path().join("k"));
        let key = TestKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let log = RotatingChainLog::open(
            &path,
            key,
            RotationConfig {
                size_cap_bytes: cap,
                max_archives: 4,
                file_mode: 0o600,
            },
            Arc::new(NoProtection),
        )
        .unwrap();
        Self {
            _dir: dir,
            path,
            log,
            pk,
        }
    }

    fn push(&mut self, b: HeartbeatRecord) {
        self.log.append(b).unwrap();
    }

    fn lines(&self) -> Vec<Vec<u8>> {
        std::fs::read(&self.path)
            .unwrap()
            .split(|c| *c == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }
}

fn kinds(r: &CheckResult) -> Vec<&'static str> {
    r.alerts.iter().map(Alert::kind).collect()
}

fn cfg() -> WatchConfig {
    WatchConfig::default()
}

/// Beats on time: the first check anchors, the next ones see the new beats
/// and say nothing.
#[test]
fn beats_on_time_raise_nothing() {
    let mut c = Chain::new();
    for i in 1..=3 {
        c.push(beat(i, 30 * i as i64));
    }
    let r = check(Ok(&c.lines()), &c.pk, None, at(95), &cfg());
    assert!(r.anchored && r.alerts.is_empty(), "{r:?}");
    assert_eq!(r.exit_code(), 0);
    let s = r.state.unwrap();
    assert_eq!(s.seq, 3);
    c.push(beat(4, 120));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(125), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    // (the age on the verifier's clock: since it first saw the beat)
    assert_eq!((r.new_beats, r.age_secs), (1, Some(0)));
    // the same tail again, still fresh: nothing new, nothing wrong
    let s = r.state.unwrap();
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(140), &cfg());
    assert!(r.alerts.is_empty() && r.new_beats == 0, "{r:?}");
}

/// Silence: no newer beat within two intervals and 15 s (75 s at 30 s),
/// and a source that cannot be read past it.
#[test]
fn silence_alerts_after_two_intervals() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    // (on the verifier's clock: from at(1), when it first saw beat 1)
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(76), &cfg());
    assert!(r.alerts.is_empty(), "within the bound: {r:?}");
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(77), &cfg());
    assert_eq!(kinds(&r), ["SILENT"]);
    assert_eq!(r.exit_code(), 10);
    let r = check(
        Err("ssh: connect timed out"),
        &c.pk,
        Some(&s),
        at(77),
        &cfg(),
    );
    assert_eq!(kinds(&r), ["SILENT"]);
    assert!(r.alerts[0].detail().contains("ssh: connect timed out"));
    // unreachable but within the bound: not yet
    let r = check(
        Err("ssh: connect timed out"),
        &c.pk,
        Some(&s),
        at(40),
        &cfg(),
    );
    assert!(r.alerts.is_empty(), "{r:?}");
    // a bound of the operator's
    let tight = WatchConfig {
        max_silence_secs: Some(10),
        ..cfg()
    };
    assert_eq!(
        kinds(&check(Ok(&c.lines()), &c.pk, Some(&s), at(12), &tight)),
        ["SILENT"]
    );
}

/// A beat altered on the way (one byte), or written with another key, is
/// tampered — and nothing else of that fetch is believed.
#[test]
fn a_tampered_beat_alerts() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    c.push(beat(2, 30));
    let s = check(Ok(&c.lines()[..1]), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    let mut lines = c.lines();
    let text = String::from_utf8(lines[1].clone()).unwrap();
    lines[1] = text.replace("\"observing\"", "\"combat\"").into_bytes();
    let r = check(Ok(&lines), &c.pk, Some(&s), at(31), &cfg());
    assert_eq!(kinds(&r), ["TAMPERED"]);
    assert_eq!(r.exit_code(), 13);
    assert_eq!(r.state.as_ref().unwrap().seq, 1, "the state is kept");
    // another agent's key
    let other = Chain::new();
    let r = check(Ok(&c.lines()), &other.pk, None, at(31), &cfg());
    assert_eq!(kinds(&r), ["TAMPERED", "TAMPERED"]);
}

/// An older beat after a newer one (a replayed export, a chain rolled back
/// on the host), a fork of a beat seen, a chain head that went back.
#[test]
fn a_replay_or_a_rollback_alerts() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let old = c.lines();
    c.push(beat(2, 30));
    c.push(beat(3, 60));
    let s = check(Ok(&c.lines()), &c.pk, None, at(61), &cfg())
        .state
        .unwrap();
    let r = check(Ok(&old), &c.pk, Some(&s), at(62), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"]);
    assert_eq!(r.exit_code(), 12);
    // another chain whose beat 3 is not the one seen (a fork)
    let mut fork = Chain::new();
    for i in 1..=3 {
        let mut b = beat(i, 30 * i as i64 - 30);
        if i == 3 {
            b.posture = "alerted".into();
        }
        fork.push(b);
    }
    let r = check(Ok(&fork.lines()), &fork.pk, Some(&s), at(62), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    // the audit chain's head went back
    let mut b = beat(4, 90);
    b.heads[0].seq = Some(50);
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    assert!(r.alerts[0].detail().contains("audit"));
}

/// Beats missing from the chain, or a fetched tail that does not link.
#[test]
fn a_broken_chain_alerts() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    for i in 2..=4 {
        c.push(beat(i, 30 * i as i64 - 30));
    }
    // the tail without beats 2 and 3
    let lines = c.lines();
    let r = check(Ok(&lines[3..]), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["BROKEN"]);
    assert_eq!(r.exit_code(), 11);
    // a line removed from the middle of the fetch
    let cut = vec![lines[0].clone(), lines[2].clone(), lines[3].clone()];
    let r = check(Ok(&cut), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["BROKEN"]);
    // the whole tail: fine
    let r = check(Ok(&lines), &c.pk, Some(&s), at(91), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
}

/// A clean stop's signed beat: the agent stopped, said every check while
/// it stays stopped.
#[test]
fn a_stop_beat_alerts() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    let mut b = beat(2, 10);
    b.kind = BeatKind::Stop;
    b.stop_reason = Some("admin_shutdown".into());
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(11), &cfg());
    assert_eq!(kinds(&r), ["STOPPED"]);
    assert!(r.alerts[0].detail().contains("admin_shutdown"));
    assert_eq!(r.exit_code(), 15);
    let s = r.state.unwrap();
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(500), &cfg());
    assert_eq!(kinds(&r), ["STOPPED"], "still stopped, not silent");
}

/// Loss since the last beat seen; a new run's counters from zero; the
/// first check (an anchor) says nothing of what the run counted before it.
#[test]
fn loss_alerts_against_the_last_beat_seen() {
    let mut c = Chain::new();
    let mut b = beat(1, 0);
    b.loss[4] = Some(3);
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg());
    assert!(r.alerts.is_empty(), "the anchor: {r:?}");
    let s = r.state.unwrap();
    let mut b = beat(2, 30);
    b.loss[4] = Some(3);
    b.loss[3] = Some(7);
    b.loss[0] = Some(2);
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(31), &cfg());
    assert_eq!(kinds(&r), ["LOSS"]);
    assert!(
        r.alerts[0].detail().contains("stage 4 (bus queue) +7"),
        "{r:?}"
    );
    assert_eq!(r.exit_code(), 14);
    // a new run: its own counters, from zero
    let s = r.state.unwrap();
    let mut b = beat(3, 60);
    b.run = "bbbbbbbbbbbbbbbb".into();
    b.kind = BeatKind::Start;
    b.loss[0] = Some(1);
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(61), &cfg());
    // (no stop beat before the new run: also DEGRADED, the agent died)
    assert_eq!(kinds(&r), ["LOSS", "DEGRADED"]);
    assert!(
        r.alerts[0].detail().contains("stage 1 (kernel ring) +1"),
        "the new run's 1 is its own loss, though the old run had counted 2: {r:?}"
    );
    assert!(
        r.alerts[1].detail().contains("without a clean stop"),
        "{r:?}"
    );
}

/// Health: a decision that stands still, a probe gap, an action row not
/// written, an interrupted action, a new degradation.
#[test]
fn degraded_health_alerts() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    let mut b = beat(2, 30);
    b.decision_since_last_ms = 61_000;
    b.probe_gaps = Some(1);
    b.actions.unwritten = 2;
    b.degradations = vec!["sensor pump exited: fs_protect".into()];
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(31), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"]);
    let d = r.alerts[0].detail();
    for want in [
        "decision thread",
        "telemetry gap",
        "not in the signed actions chain",
        "fs_protect",
    ] {
        assert!(d.contains(want), "{want}: {d}");
    }
    assert_eq!(r.exit_code(), 16);
    let mut b = beat(3, 60);
    b.run = "cccccccccccccccc".into();
    b.kind = BeatKind::Start;
    b.actions.interrupted_at_boot = 1;
    c.push(b);
    let s = r.state.unwrap();
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(61), &cfg());
    assert!(r.alerts[0].detail().contains("interrupted"), "{r:?}");
}

/// A beat stamped in the future: the agent's clock ahead of the
/// verifier's — DEGRADED, never TAMPERED (review of #478, X1: an NTP
/// misconfigured is not a compromise); the most severe alert gives the
/// exit code.
#[test]
fn a_future_beat_and_the_exit_code_order() {
    let mut c = Chain::new();
    c.push(beat(1, 600));
    let r = check(Ok(&c.lines()), &c.pk, None, at(0), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"], "{r:?}");
    assert!(
        r.alerts[0].detail().contains("ahead of the verifier's"),
        "{r:?}"
    );
    let r = CheckResult {
        alerts: vec![
            Alert::Degraded(String::new()),
            Alert::Silent(String::new()),
            Alert::Loss(String::new()),
        ],
        state: None,
        new_beats: 0,
        age_secs: None,
        anchored: false,
        notices: Vec::new(),
    };
    assert_eq!(r.exit_code(), 10, "silence is more severe than loss");
}

/// The wire form of a beat (SCHEMA FREEZE).
#[test]
fn beat_rows_are_pinned() {
    assert_eq!(
        serde_json::to_string(&{
            let mut b = beat(2, 30);
            b.heads.push(BeatHead {
                chain: "actions".into(),
                file: Some(3),
                bytes: Some(8_192),
                hash: "cd".repeat(32),
                ..BeatHead::default()
            });
            b
        })
        .unwrap(),
        r#"{"kind":"beat","seq":2,"ts":"2026-11-01T10:00:30.000000Z","agent_id":"0011","run":"aaaaaaaaaaaaaaaa","boot_id":"b007","uptime_ms":30000,"interval_secs":30,"version":"0.0.1","posture":"observing","trust_level":"L3","degradations":[],"decision_rounds":120,"decision_since_last_ms":400,"loss":[0,0,0,0,0,0,0],"actions":{"intents":0,"outcomes":0,"unwritten":0,"interrupted_at_boot":0,"in_flight":0},"probe_gaps":0,"heads":[{"chain":"audit","seq":102,"hash":"0000000000000000000000000000000000000000000000000000000000000066"},{"chain":"actions","file":3,"bytes":8192,"hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}]}"#
    );
    use crate::chainlog::ChainPayload;
    assert_eq!(HeartbeatRecord::KIND, "heartbeat");
}

/// Whoever holds the key can sign beats; what such a chain cannot do unseen:
/// continue the beat seen without linking to it, splice two chains at
/// contiguous numbers, skip a number, number its beats below the one seen,
/// or stamp its next beat before the one seen.
#[test]
fn a_chain_rebuilt_with_the_key_is_seen() {
    let mut c = Chain::new();
    for i in 1..=3 {
        c.push(beat(i, 30 * i as i64 - 30));
    }
    let s = check(Ok(&c.lines()[..1]), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    // another chain, the same key, the same numbers: its beat 2 does not
    // link to the beat 1 seen
    let mut other = Chain::sharing_key(&c);
    let mut b = beat(1, 0);
    b.posture = "alerted".into();
    other.push(b);
    other.push(beat(2, 30));
    other.push(beat(3, 60));
    let r = check(Ok(&other.lines()[1..]), &c.pk, Some(&s), at(61), &cfg());
    assert_eq!(kinds(&r), ["BROKEN"], "{r:?}");
    // a fetched tail spliced from the two chains at contiguous numbers
    let lines = c.lines();
    let spliced = vec![lines[0].clone(), lines[1].clone(), other.lines()[2].clone()];
    let r = check(Ok(&spliced), &c.pk, None, at(61), &cfg());
    assert_eq!(kinds(&r), ["BROKEN"], "{r:?}");
    // a gap in the numbers of a chain that links
    let mut gap = Chain::new();
    gap.push(beat(1, 0));
    gap.push(beat(2, 30));
    gap.push(beat(4, 60));
    let r = check(Ok(&gap.lines()), &gap.pk, None, at(61), &cfg());
    assert_eq!(kinds(&r), ["BROKEN"], "{r:?}");
    // beats numbered from 1 again, stamped after the beat seen, their heads
    // ahead: older only by number
    let s3 = check(Ok(&c.lines()), &c.pk, None, at(61), &cfg())
        .state
        .unwrap();
    let mut renum = Chain::sharing_key(&c);
    for (i, t) in [(1, 100), (2, 130)] {
        let mut b = beat(i, t);
        b.heads[0].seq = Some(200 + i);
        renum.push(b);
    }
    let r = check(Ok(&renum.lines()), &c.pk, Some(&s3), at(131), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    // the next beat, in order and linked, stamped before the beat seen:
    // the agent's clock went back — DEGRADED, not REPLAY (review of #478)
    c.push(beat(4, 50));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s3), at(62), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"], "{r:?}");
    assert!(r.alerts[0].detail().contains("clock went back"), "{r:?}");
}

/// Review of #476: the actions chain's head is in each beat (its position
/// and hash): a tail cut from it on the host shows as a position that went
/// back; a rotation (the next file, from its start) does not; the same
/// position with another hash is a rewrite.
#[test]
fn a_tail_cut_from_the_actions_chain_alerts() {
    let actions = |file: u64, bytes: u64, h: u8| BeatHead {
        chain: "actions".into(),
        file: Some(file),
        bytes: Some(bytes),
        hash: format!("{h:02x}").repeat(32),
        ..BeatHead::default()
    };
    // grown, then rotated (the next file, from its start): no alert
    let heads = [(3, 8_192, 1), (3, 9_000, 2), (4, 300, 3)];
    let base = Chain::new();
    // the same beats signed with the same key are the same lines
    let build = |next: Option<BeatHead>| {
        let mut c = Chain::sharing_key(&base);
        for (i, &(f, b, h)) in heads.iter().enumerate() {
            let mut x = beat(i as u64 + 1, 30 * i as i64);
            x.heads.push(actions(f, b, h));
            c.push(x);
        }
        if let Some(n) = next {
            let mut x = beat(4, 90);
            x.heads.push(n);
            c.push(x);
        }
        c
    };
    let c = build(None);
    let lines = c.lines();
    let mut s = check(Ok(&lines[..1]), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    for n in 2..=3 {
        let r = check(Ok(&lines[..n]), &c.pk, Some(&s), at(30 * n as i64), &cfg());
        assert!(r.alerts.is_empty(), "{r:?}");
        s = r.state.unwrap();
    }
    // its tail cut
    let cut = build(Some(actions(4, 100, 4)));
    let r = check(Ok(&cut.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    assert!(r.alerts[0].detail().contains("file 4 at byte 100"), "{r:?}");
    // the same position, another hash: rewritten
    let rw = build(Some(actions(4, 300, 9)));
    let r = check(Ok(&rw.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    // a rotation undone
    let back = build(Some(actions(3, 9_500, 5)));
    let r = check(Ok(&back.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    // the head gone from the beat (the chain did not open on the host)
    let mut gone = beat(4, 90);
    gone.heads.retain(|h| h.chain != "actions");
    let mut gone_chain = Chain::sharing_key(&base);
    for (i, &(f, b, h)) in heads.iter().enumerate() {
        let mut x = beat(i as u64 + 1, 30 * i as i64);
        x.heads.push(actions(f, b, h));
        gone_chain.push(x);
    }
    gone_chain.push(gone);
    let r = check(Ok(&gone_chain.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    assert!(r.alerts[0].detail().contains("not in the beat"), "{r:?}");
    // cut, then appended past the position seen: the agent's own read-back
    // says the head it named is gone
    let mut cut_past = actions(4, 5_000, 7);
    cut_past.kept = Some(false);
    let r = check(
        Ok(&build(Some(cut_past)).lines()),
        &c.pk,
        Some(&s),
        at(91),
        &cfg(),
    );
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    assert!(r.alerts[0].detail().contains("no longer holds"), "{r:?}");
    // grown again: fine
    let ok = build(Some(actions(4, 900, 6)));
    let r = check(Ok(&ok.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
}

/// The lab's freeze (ended by the watchdog before the silence bound): a
/// beat 71 s after the one before it, every 30 s, is DEGRADED; a new run's
/// start beat after a long gap is not (a restart).
#[test]
fn a_late_beat_says_the_agent_stood_still() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    c.push(beat(2, 30));
    let s = check(Ok(&c.lines()), &c.pk, None, at(31), &cfg())
        .state
        .unwrap();
    c.push(beat(3, 101));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(102), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"], "{r:?}");
    assert!(
        r.alerts[0]
            .detail()
            .contains("beat 3 came 71 s after beat 2"),
        "{r:?}"
    );
    // on time again: nothing
    let s = r.state.unwrap();
    c.push(beat(4, 131));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(132), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    // a clean restart: a stop beat, then a start beat of a new run, long
    // after — STOPPED, then nothing more (no stall, no death)
    let s = r.state.unwrap();
    let mut stop = beat(5, 140);
    stop.kind = BeatKind::Stop;
    stop.stop_reason = Some("admin_shutdown".into());
    c.push(stop);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(141), &cfg());
    assert_eq!(kinds(&r), ["STOPPED"], "{r:?}");
    let s = r.state.unwrap();
    let mut b = beat(6, 400);
    b.kind = BeatKind::Start;
    b.run = "bbbbbbbbbbbbbbbb".into();
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(401), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    // a clean stop and the next run's start, both new in one fetch: not a
    // death either
    let s = r.state.unwrap();
    c.push(beat(7, 430));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(431), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    let s = r.state.unwrap();
    let mut stop = beat(8, 440);
    stop.kind = BeatKind::Stop;
    stop.run = "bbbbbbbbbbbbbbbb".into();
    stop.stop_reason = Some("admin_shutdown".into());
    c.push(stop);
    let mut b = beat(9, 450);
    b.kind = BeatKind::Start;
    b.run = "dddddddddddddddd".into();
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(451), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    // a restart with no stop beat before it (killed, crashed, frozen and
    // restarted by the watchdog — the lab's freeze): DEGRADED, however
    // soon it came back
    let s = r.state.unwrap();
    let mut b = beat(10, 470);
    b.run = "dddddddddddddddd".into();
    c.push(b);
    let mut b = beat(11, 480);
    b.kind = BeatKind::Start;
    b.run = "cccccccccccccccc".into();
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(481), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"], "{r:?}");
    assert!(
        r.alerts[0].detail().contains("without a clean stop"),
        "{r:?}"
    );
}

/// The read-back of a head (`chainlog::holds_line_ending_at`): the line
/// that ends at the byte named, with the hash named — not any line there.
#[test]
fn a_head_is_held_only_by_its_own_line() {
    use crate::chainlog::holds_line_ending_at;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("c.jsonl");
    let a = r#"{"entry_hash":"aaaa"}"#;
    let b = r#"{"entry_hash":"bbbb"}"#;
    std::fs::write(&p, format!("{a}\n{b}\n")).unwrap();
    let end = (a.len() + b.len() + 2) as u64;
    assert!(holds_line_ending_at(&p, end, "bbbb").unwrap());
    assert!(holds_line_ending_at(&p, (a.len() + 1) as u64, "aaaa").unwrap());
    // rewritten in place, the same length: another hash at that byte
    let b2 = r#"{"entry_hash":"cccc"}"#;
    std::fs::write(&p, format!("{a}\n{b2}\n")).unwrap();
    assert!(!holds_line_ending_at(&p, end, "bbbb").unwrap());
    // cut, then appended past: mid-line at that byte
    std::fs::write(&p, format!("{a}\n{{\"entry_hash\":\"dddd-longer\"}}\n")).unwrap();
    assert!(!holds_line_ending_at(&p, end, "bbbb").unwrap());
    // cut short of it
    std::fs::write(&p, format!("{a}\n")).unwrap();
    assert!(!holds_line_ending_at(&p, end, "bbbb").unwrap());
    assert!(holds_line_ending_at(&dir.path().join("none"), 1, "x").is_err());
}

/// Review of #478 (X1): the host's clock decides nothing grave. A reboot
/// with the RTC 40 s behind (a clean stop at 100 s, the next run's start
/// stamped 60 s; numbers and links in order): DEGRADED "clock went back",
/// not REPLAY. The host's clock 40 s ahead of the verifier's: DEGRADED,
/// not TAMPERED. An NTP step between two beats (their stamps 200 s apart,
/// their uptimes 30 s): no late beat — lateness is the agent's uptime.
/// Silence is the verifier's clock: a host clock far ahead does not keep a
/// dead agent "fresh".
#[test]
fn the_host_s_clock_decides_nothing_grave() {
    let mut c = Chain::new();
    c.push(beat(1, 70));
    let mut stop = beat(2, 100);
    stop.kind = BeatKind::Stop;
    stop.stop_reason = Some("host shutdown".into());
    c.push(stop);
    let s = check(Ok(&c.lines()), &c.pk, None, at(101), &cfg())
        .state
        .unwrap();
    let mut start = beat(3, 60);
    start.kind = BeatKind::Start;
    start.run = "bbbbbbbbbbbbbbbb".into();
    start.uptime_ms = 1_000;
    c.push(start);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(130), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"], "{r:?}");
    assert!(r.alerts[0].detail().contains("clock went back"), "{r:?}");
    // the host's clock ahead
    let s = r.state.unwrap();
    let mut ahead = beat(4, 200);
    ahead.run = "bbbbbbbbbbbbbbbb".into();
    ahead.uptime_ms = 31_000;
    c.push(ahead);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(160), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"], "{r:?}");
    assert!(
        r.alerts[0].detail().contains("ahead of the verifier's"),
        "{r:?}"
    );
    // an NTP step: stamps far apart, uptimes 30 s apart — not late
    let s = r.state.unwrap();
    let mut stepped = beat(5, 400);
    stepped.run = "bbbbbbbbbbbbbbbb".into();
    stepped.uptime_ms = 61_000;
    c.push(stepped);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(400), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    // the agent dead, its last beat stamped in the far future: silent on
    // the verifier's clock all the same
    let s = r.state.unwrap();
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(400 + 76), &cfg());
    assert_eq!(kinds(&r), ["SILENT"], "{r:?}");
}

/// Review of #478 (its V2): an export right after the chain rotated — a
/// short active file — reads the newest archive's tail too: the verifier
/// sees the beats it missed linked through the rotation's terminator, not
/// a false BROKEN.
#[test]
fn an_export_after_a_rotation_links_through_it() {
    let mut c = Chain::capped(4 * 1024);
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    let mut i = 2;
    while crate::chainlog::archives_newest_first(&c.path).is_empty() {
        c.push(beat(i, 30 * (i as i64 - 1)));
        i += 1;
    }
    c.push(beat(i, 30 * (i as i64 - 1)));
    let active = std::fs::read_to_string(&c.path).unwrap().lines().count();
    assert!(active < 16, "a short active file: {active}");
    let raw: Vec<Vec<u8>> = tail_lines(&c.path, 64)
        .unwrap()
        .into_iter()
        .map(String::into_bytes)
        .collect();
    assert!(raw.len() > active, "the archive's tail read too");
    let r = check(
        Ok(&raw),
        &c.pk,
        Some(&s),
        at(30 * (i as i64 - 1) + 1),
        &cfg(),
    );
    assert!(
        !r.alerts.iter().any(|a| matches!(a, Alert::Broken(_))),
        "{r:?}"
    );
    assert_eq!(r.new_beats, i - 1, "{r:?}");
}

/// Review of #478 (its V5): the audit log's head at the same row with
/// another hash — the row rewritten — is REPLAY.
#[test]
fn an_audit_head_rewritten_at_the_same_row_alerts() {
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    let mut b = beat(2, 30);
    b.heads[0].seq = Some(101);
    b.heads[0].hash = "ee".repeat(32);
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(31), &cfg());
    assert_eq!(kinds(&r), ["REPLAY"], "{r:?}");
    assert!(
        r.alerts[0]
            .detail()
            .contains("audit chain's head went back"),
        "{r:?}"
    );
}

/// R13 (lab PR 271): a settled capability manifest whose hash moves is
/// DEGRADED, within a run or across a restart; the first check anchors it;
/// an unsettled one is not compared, and is DEGRADED only past its bound.
#[test]
fn a_capability_manifest_change_is_degraded() {
    let mut c = Chain::new();
    c.push(beat_m(1, 0, "a", 0, false));
    c.push(beat_m(2, 30, "b", 1, true));
    let r = check(Ok(&c.lines()), &c.pk, None, at(31), &cfg());
    assert!(r.alerts.is_empty(), "the first check anchors: {r:?}");
    let s = r.state.unwrap();
    assert_eq!(s.manifest_hash.as_deref(), Some("b".repeat(64).as_str()));
    assert_eq!(s.manifest_revision, Some(1));
    // the same hash again: quiet
    c.push(beat_m(3, 60, "b", 1, true));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(61), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    let s = r.state.unwrap();
    // a runtime change (a probe's gap): DEGRADED, naming both hashes
    c.push(beat_m(4, 90, "c", 2, true));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"]);
    let d = r.alerts[0].detail();
    assert!(
        d.contains("the capability manifest changed: bbbbbbbbbbbbbbbb → cccccccccccccccc")
            && d.contains("revision 2")
            && !d.contains("across a restart"),
        "{d}"
    );
    assert_eq!(r.exit_code(), 16);
    let s = r.state.unwrap();
    // a change and its undoing between two checks: still seen
    c.push(beat_m(5, 120, "d", 3, true));
    c.push(beat_m(6, 150, "c", 4, true));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(151), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"]);
    let d = r.alerts[0].detail();
    assert!(
        d.contains("→ dddd") && d.contains("dddddddddddddddd → cccc"),
        "{d}"
    );
    let s = r.state.unwrap();
    // a clean stop and a new run: its unsettled start beat is not compared;
    // its settled hash, another one, is a change across the restart
    let mut stop = beat_m(7, 160, "c", 4, true);
    stop.kind = BeatKind::Stop;
    stop.stop_reason = Some("sigterm".into());
    c.push(stop);
    let mut start = beat_m(8, 170, "e", 0, false);
    start.kind = BeatKind::Start;
    start.run = "bbbbbbbbbbbbbbbb".into();
    start.uptime_ms = 500;
    c.push(start);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(171), &cfg());
    assert!(
        !r.alerts.iter().any(|a| a.detail().contains("manifest")),
        "unsettled: not compared {r:?}"
    );
    let s = r.state.unwrap();
    assert_eq!(s.manifest_hash.as_deref(), Some("c".repeat(64).as_str()));
    let mut b = beat_m(9, 200, "f", 1, true);
    b.run = "bbbbbbbbbbbbbbbb".into();
    b.uptime_ms = 30_500;
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(201), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"]);
    assert!(
        r.alerts[0].detail().contains("changed across a restart"),
        "{r:?}"
    );
    // the same settled hash after a restart: quiet
    let s = r.state.unwrap();
    let mut b = beat_m(10, 230, "f", 1, true);
    b.run = "bbbbbbbbbbbbbbbb".into();
    b.uptime_ms = 60_500;
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(231), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
}

/// R13: a manifest that does not settle within its bound, and a beat that
/// no longer carries one, are DEGRADED.
#[test]
fn an_unsettled_or_missing_manifest_is_degraded() {
    let mut c = Chain::new();
    c.push(beat_m(1, 0, "a", 0, true));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    let mut b = beat_m(2, 30, "a", 0, false);
    b.uptime_ms = MANIFEST_SETTLE_SECS * 1000;
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(31), &cfg());
    assert!(r.alerts.is_empty(), "within its bound: {r:?}");
    let s = r.state.unwrap();
    let mut b = beat_m(3, 60, "a", 0, false);
    b.uptime_ms = MANIFEST_SETTLE_SECS * 1000 + 1;
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(61), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"]);
    assert!(r.alerts[0].detail().contains("has not settled"), "{r:?}");
    let s = r.state.unwrap();
    c.push(beat(4, 90));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(91), &cfg());
    assert_eq!(kinds(&r), ["DEGRADED"]);
    assert!(
        r.alerts[0]
            .detail()
            .contains("no capability manifest any more"),
        "{r:?}"
    );
    // a beat without one, and no manifest ever seen: nothing to say
    let mut c = Chain::new();
    c.push(beat(1, 0));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    c.push(beat(2, 30));
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(31), &cfg());
    assert!(r.alerts.is_empty(), "{r:?}");
    assert_eq!(r.state.unwrap().manifest_hash, None);
}

/// The review of #479: the sensor contract's hash changing alone (an
/// upgrade, a new kernel) is a notice, not an alert; with the capabilities
/// it is both.
#[test]
fn a_contract_change_alone_is_a_notice() {
    let mut c = Chain::new();
    c.push(beat_m(1, 0, "a", 1, true));
    let s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    assert_eq!(
        s.manifest_contract.as_deref(),
        Some("c1".repeat(32).as_str())
    );
    let mut b = beat_m(2, 30, "a", 1, true);
    b.capabilities.as_mut().unwrap().contract = Some("c2".repeat(32));
    b.version = "0.0.2".into();
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(31), &cfg());
    assert!(r.alerts.is_empty(), "an upgrade alone: {r:?}");
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.notices.len(), 1, "{r:?}");
    assert!(
        r.notices[0]
            .starts_with("the sensor contract changed: c1c1c1c1c1c1c1c1 → c2c2c2c2c2c2c2c2")
            && r.notices[0].contains("agent 0.0.2"),
        "{r:?}"
    );
    let s = r.state.unwrap();
    // the same contract again: nothing to say
    // beat 3 carries c1 again (the helper's), beat 4 c2
    c.push(beat_m(3, 60, "a", 1, true));
    let mut b = beat_m(4, 90, "b", 2, true);
    b.capabilities.as_mut().unwrap().contract = Some("c2".repeat(32));
    c.push(b);
    let r = check(Ok(&c.lines()), &c.pk, Some(&s), at(91), &cfg());
    // beat 3 (c1, agent 0.0.1 after 0.0.2) went backwards — DEGRADED (the
    // re-check of #479); beat 4 (c2, the same versions): a notice; the
    // capabilities changed — DEGRADED
    assert_eq!(kinds(&r), ["DEGRADED"]);
    assert_eq!(r.notices.len(), 1, "{r:?}");
    let Alert::Degraded(d) = &r.alerts[0] else {
        unreachable!()
    };
    assert!(
        d.contains("the sensor contract changed backwards: c2c2c2c2c2c2c2c2 → c1c1c1c1c1c1c1c1")
            && d.contains("agent 0.0.2 → 0.0.1 (older)")
            && d.contains("the capability manifest changed"),
        "{d}"
    );
    // the first check anchors the contract too: no notice
    let r = check(Ok(&c.lines()), &c.pk, None, at(91), &cfg());
    assert!(r.notices.is_empty() && r.alerts.is_empty(), "{r:?}");
}

/// The re-check of #479: a contract change is a notice only when the
/// agent's version, the contract's version and the kernel's release each
/// advanced or stayed; one going backwards (a downgrade, an older kernel),
/// or a release not known to be newer, is DEGRADED.
#[test]
fn a_contract_going_backwards_is_degraded() {
    let with = |seq: u64, c: &str, agent: &str, version: u32, kernel: &str| {
        let mut b = beat_m(seq, 30 * seq as i64, "a", 1, true);
        b.version = agent.into();
        let m = b.capabilities.as_mut().unwrap();
        m.contract = Some(c.repeat(32));
        m.contract_version = Some(version);
        m.kernel = Some(kernel.into());
        b
    };
    let mut c = Chain::new();
    c.push(with(1, "c1", "0.0.2", 1, "6.8.0-147-generic"));
    let mut s = check(Ok(&c.lines()), &c.pk, None, at(1), &cfg())
        .state
        .unwrap();
    assert_eq!(
        s.manifest_versions,
        Some(ContractSeen {
            agent: "0.0.2".into(),
            contract_version: Some(1),
            kernel: Some("6.8.0-147-generic".into()),
        })
    );
    // (beat, its contract, agent, contract version, kernel, what is said)
    let steps: [(&str, &str, u32, &str, Option<&str>); 6] = [
        (
            "c2",
            "0.0.1",
            1,
            "6.8.0-147-generic",
            Some("agent 0.0.2 → 0.0.1 (older)"),
        ),
        ("c3", "0.0.3", 1, "6.8.0-147-generic", None),
        (
            "c4",
            "0.0.3",
            1,
            "6.8.0-140-generic",
            Some("kernel 6.8.0-147-generic → 6.8.0-140-generic (older)"),
        ),
        ("c5", "0.0.3", 1, "6.8.0-150-generic", None),
        (
            "c6",
            "0.0.3",
            0,
            "6.8.0-150-generic",
            Some("contract version 1 → 0 (older)"),
        ),
        (
            "c7",
            "0.0.3",
            1,
            "6.8.0-150-lowlatency",
            Some("kernel 6.8.0-150-generic → 6.8.0-150-lowlatency (not known to be newer)"),
        ),
    ];
    for (i, (contract, agent, version, kernel, said)) in steps.into_iter().enumerate() {
        let seq = i as u64 + 2;
        c.push(with(seq, contract, agent, version, kernel));
        let r = check(
            Ok(&c.lines()),
            &c.pk,
            Some(&s),
            at(30 * seq as i64 + 1),
            &cfg(),
        );
        match said {
            Some(back) => {
                assert_eq!(kinds(&r), ["DEGRADED"], "{contract}: {r:?}");
                assert!(r.notices.is_empty(), "{contract}: {r:?}");
                let Alert::Degraded(d) = &r.alerts[0] else {
                    unreachable!()
                };
                assert!(
                    d.starts_with("the sensor contract changed backwards") && d.contains(back),
                    "{contract}: {d}"
                );
            }
            None => {
                assert!(r.alerts.is_empty(), "{contract}, forward: {r:?}");
                assert_eq!(r.notices.len(), 1, "{contract}: {r:?}");
                assert!(r.notices[0].starts_with("the sensor contract changed:"));
            }
        }
        s = r.state.unwrap();
    }
}

/// The re-check of #479: releases compared part by part, numbers as
/// numbers; a part that differs and is not a number on both sides is not
/// an order.
#[test]
fn releases_are_ordered_part_by_part() {
    use std::cmp::Ordering::*;
    let cases = [
        ("0.0.2", "0.0.1", Some(Greater)),
        ("0.0.1", "0.0.2", Some(Less)),
        ("0.10.0", "0.9.9", Some(Greater)),
        ("0.0.1", "0.0.1", Some(Equal)),
        ("6.8.0-150-generic", "6.8.0-147-generic", Some(Greater)),
        ("5.15.0-202-generic", "6.8.0-147-generic", Some(Less)),
        ("6.8.0-147-generic", "6.8.0-147-lowlatency", None),
        ("6.8.0.1", "6.8.0", Some(Greater)),
        ("6.8.0", "6.8.0.1", Some(Less)),
        ("6.8.0-rc1", "6.8.0", None),
        ("1.0.0-rc2", "1.0.0-rc1", None),
    ];
    for (a, b, want) in cases {
        assert_eq!(release_order(a, b), want, "{a} vs {b}");
    }
    let seen = ContractSeen {
        agent: "0.0.2".into(),
        contract_version: Some(1),
        kernel: Some("6.8.0-147-generic".into()),
    };
    assert!(contract_backwards(&seen, &seen).is_empty());
    let older_agent_without_fields = ContractSeen {
        agent: "0.0.2".into(),
        contract_version: None,
        kernel: None,
    };
    assert_eq!(
        contract_backwards(&seen, &older_agent_without_fields),
        [
            "kernel 6.8.0-147-generic → (not said) (not known to be newer)",
            "contract version 1 → (not said)"
        ]
    );
    // nothing known before: nothing to compare
    assert!(contract_backwards(&older_agent_without_fields, &seen).is_empty());
}
