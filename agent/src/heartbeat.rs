//! Wave 4 restructure, R12c-2 (lab PR 270; plan §3.4, report 06 INI-14):
//! the signed heartbeat and the signed `telemetry_loss` rows.
//!
//! **The heartbeat.** Every [`DEFAULT_INTERVAL_SECS`] (`NN_HEARTBEAT_SECS`,
//! 5 to 300; never off) a task of its own appends a beat
//! ([`nn_evidence::heartbeat::HeartbeatRecord`]) to the `heartbeat` chain
//! (`/var/lib/northnarrow/heartbeat.jsonl`, `--heartbeat-file`: rotating, 4
//! MiB × 4 archives, signed with the agent's key, each line chained to the
//! one before): its number (continuing across runs), the time, the run, the
//! loss counters of stages 1 to 7, the actions chain's counts, the telemetry
//! probe's gaps, the decision thread's progress, the posture, the ladder's
//! stage, the trust level, the degradations, and the heads of the audit and
//! actions chains. The run's first beat is a `start` beat; a clean stop
//! writes a `stop` beat with its reason ([`Heartbeat::stop`]). A verifier on
//! another host (`nn-admin heartbeat watch`, `docs/operator/HEARTBEAT.md`)
//! reads the newest lines (`nn-admin heartbeat export`, through an SSH
//! forced command) and alerts on silence, a broken chain, a replay, a
//! tampered beat, loss, a stop, degraded health.
//!
//! **`telemetry_loss`.** At each beat the loss of every stage (1 to 7: the
//! kernel's ring and budget, the decoder, the bus's queues, the decision's
//! delay, the response queue, the evidence writers) is compared with the
//! last signed row: a change is signed in the audit log
//! (`telemetry_loss`, the totals since the run started and what each stage
//! lost since the last row) at most once a minute; with no change, one row
//! an hour says so (the count of zero signed too).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_evidence::heartbeat::{BeatActions, BeatHead, BeatKind, HeartbeatRecord, MAX_DEGRADATIONS};
use parking_lot::Mutex;
use tracing::{error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// The heartbeat chain's active file.
pub const DEFAULT_HEARTBEAT_LOG_PATH: &str = "/var/lib/northnarrow/heartbeat.jsonl";
/// The beats' period (nn-linux's: the self-integrity check reports a
/// weakening value).
pub use nn_linux::heartbeat_config::{
    interval_from_env, interval_weakens, DEFAULT_INTERVAL_SECS, INTERVAL_ENV,
};
/// The chain's rotation: 4 MiB × 4 archives (a beat ≈ 1 KiB: days of
/// beats at 30 s).
pub const HEARTBEAT_CAP_BYTES: u64 = 4 * 1024 * 1024;
pub const HEARTBEAT_MAX_ARCHIVES: usize = 4;
/// Audit op of a loss row.
pub const TELEMETRY_LOSS_OP: &str = "telemetry_loss";
/// A changed loss is signed at most this often; an unchanged one this
/// often.
const LOSS_ROW_EVERY_CHANGED: Duration = Duration::from_secs(60);
const LOSS_ROW_EVERY_UNCHANGED: Duration = Duration::from_secs(3600);

/// What a beat reads, each from its owner.
pub struct Sources {
    pub agent_id: [u8; 16],
    pub run: String,
    pub posture: crate::posture::PostureMachine,
    pub ladder: Option<Arc<crate::combat::CombatLadder>>,
    /// R13 (lab PR 271): the signed capability manifest — the beat's trust
    /// level and degradations are its newest revision's, and the beat
    /// carries its hash.
    pub manifest: Option<crate::boot::manifest::SignedManifest>,
    pub bus: Option<crate::sensors::bus::BusStats>,
    pub dispatch: Option<crate::admin_socket::ResponseDispatchSource>,
    pub journal: crate::response::journal::ActionJournal,
    pub audit: Option<Arc<Mutex<AuditLog>>>,
    pub probe_on: bool,
    /// Lot 276: the export (`None`: none configured).
    pub export: Option<crate::export::ExportHandle>,
}

/// The loss of stages 1 to 8 now (`None`: a stage not counted here).
fn loss_now(s: &Sources) -> Vec<Option<u64>> {
    let dispatch = s.dispatch.as_ref().map(|f| f());
    let queues = s.bus.as_ref().map(|b| b.snapshot()).unwrap_or_default();
    let stages = crate::sensors::bus::loss_stages(
        &crate::sensors::ring_drops::snapshot(),
        crate::sensors::reject::total(),
        &queues,
        dispatch.as_ref().map(|d| (d.stage6(), d.stage7())),
        s.export.as_ref().and_then(|e| e.lost()),
    );
    let mut out: Vec<Option<u64>> = stages
        .into_iter()
        .filter(|st| (1..=8).contains(&st.stage))
        .map(|st| st.total)
        .collect();
    if s.bus.is_none() {
        // no bus (tests): stages 4 and 5 are not counted
        for i in [3usize, 4] {
            if let Some(x) = out.get_mut(i) {
                *x = None;
            }
        }
    }
    out.resize(nn_evidence::heartbeat::STAGE_NAMES.len(), None);
    out
}

/// The kernel's boot id.
fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

struct Writer {
    log: Option<crate::chainlog::RotatingChainLog<HeartbeatRecord>>,
    next_seq: u64,
    beats: u64,
    unwritten: u64,
    /// The loss signed last, and when.
    loss_row: Option<(Vec<Option<u64>>, Instant)>,
    /// The actions chain's head the last beat named (at the start: the
    /// last run's last beat's), read back at each beat (`kept`).
    actions_head: Option<Head>,
}

/// The heartbeat (see the module's doc). Cheap to clone.
#[derive(Clone)]
pub struct Heartbeat {
    inner: Arc<Mutex<Writer>>,
    sources: Arc<Sources>,
    interval: Duration,
    started: Instant,
    boot_id: Arc<String>,
}

impl Heartbeat {
    /// Open the chain at `path` (signed with `key`) and write the run's
    /// `start` beat. A chain that does not open leaves the heartbeat off
    /// (an ERROR and a signed degradation; the verifier off the host sees
    /// the silence).
    pub fn open(
        path: &Path,
        key: crate::keys::AgentSigningKey,
        protection: Arc<dyn crate::chainlog::ProtectionManager>,
        rotation_on: bool,
        sources: Sources,
    ) -> Self {
        let cfg = crate::chainlog::RotationConfig {
            size_cap_bytes: if rotation_on {
                HEARTBEAT_CAP_BYTES
            } else {
                u64::MAX
            },
            max_archives: HEARTBEAT_MAX_ARCHIVES,
            file_mode: crate::chainlog::STATE_LOG_FILE_MODE,
        };
        let log = match crate::chainlog::RotatingChainLog::open(path, key, cfg, protection) {
            Ok(l) => Some(l),
            Err(e) => {
                error!(
                    error = %format!("{e:#}"),
                    path = %path.display(),
                    "the heartbeat chain did not open — no beat this run (a verifier off the \
                     host sees the silence)"
                );
                None
            }
        };
        let (last, actions_head) = last_beat(path);
        let next_seq = last + 1;
        let hb = Self {
            inner: Arc::new(Mutex::new(Writer {
                log,
                next_seq,
                beats: 0,
                unwritten: 0,
                loss_row: None,
                actions_head,
            })),
            sources: Arc::new(sources),
            interval: interval_from_env(),
            started: Instant::now(),
            boot_id: Arc::new(boot_id()),
        };
        hb.beat(BeatKind::Start, None);
        hb
    }

    /// The beats' period.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Beats written this run, and beats the chain refused.
    pub fn counts(&self) -> (u64, u64) {
        let w = self.inner.lock();
        (w.beats, w.unwritten)
    }

    /// Run the periodic beats on the runtime.
    pub fn spawn(&self) {
        let hb = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(hb.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // the start beat was the first
            loop {
                tick.tick().await;
                let h = hb.clone();
                // the chain's append (an fsync) and the reads off the
                // runtime's worker
                let _ = tokio::task::spawn_blocking(move || h.beat(BeatKind::Beat, None)).await;
            }
        });
        info!(
            interval_secs = self.interval.as_secs(),
            "heartbeat armed — a signed beat every interval (nn-admin heartbeat export / watch)"
        );
    }

    /// A clean stop's last beat, with its reason.
    pub fn stop(&self, reason: &str) {
        self.beat(BeatKind::Stop, Some(reason));
    }

    /// Write one beat (and the loss row when due).
    pub fn beat(&self, kind: BeatKind, stop_reason: Option<&str>) {
        let s = &self.sources;
        let loss = loss_now(s);
        let j = s.journal.counts();
        let progress = crate::loop_progress::snapshot();
        let mut heads = Vec::new();
        if let Some(a) = &s.audit {
            let a = a.lock();
            heads.push(BeatHead {
                chain: "audit".into(),
                seq: a.rows().checked_sub(1),
                hash: a.last_hash().to_string(),
                ..BeatHead::default()
            });
        }
        let named = self.inner.lock().actions_head.clone();
        let now_head = s.journal.head();
        if let Some((file, bytes, hash)) = now_head.clone() {
            // the head the last beat named, still in the chain? (the review
            // of #476: a tail cut, even one appended past, is seen off the
            // host)
            let kept = named.and_then(|(f, b, h)| s.journal.holds(f, b, &h));
            if kept == Some(false) {
                error!(
                    "the actions chain no longer holds the head the last beat named — its tail \
                     was cut or rewritten (signed in this beat)"
                );
            }
            heads.push(BeatHead {
                chain: "actions".into(),
                file: Some(file),
                bytes: Some(bytes),
                hash,
                kept,
                ..BeatHead::default()
            });
        }
        // R13: the newest revision of the capability manifest (built again
        // first: a change is signed before the beat names it)
        let manifest = s.manifest.as_ref().and_then(|m| {
            // the stop signs what is pending (the review of #479: at most
            // one change row a minute, none left unsigned)
            if kind == BeatKind::Stop {
                m.flush();
            } else {
                m.refresh();
            }
            m.current()
        });
        let mut degradations = match &manifest {
            Some(m) => m.degradations.clone(),
            None => crate::boot::degradation::snapshot(),
        };
        degradations.truncate(MAX_DEGRADATIONS);
        let mut w = self.inner.lock();
        if now_head.is_some() {
            w.actions_head = now_head;
        }
        let record = HeartbeatRecord {
            kind,
            seq: w.next_seq,
            ts: crate::detection_store::now_ts(),
            agent_id: hex::encode(s.agent_id),
            run: s.run.clone(),
            boot_id: self.boot_id.as_str().to_string(),
            uptime_ms: self.started.elapsed().as_millis() as u64,
            interval_secs: self.interval.as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            posture: s.posture.current_kind().as_str().to_ascii_lowercase(),
            combat_stage: s
                .ladder
                .as_ref()
                .and_then(|l| l.current_stage())
                .map(|st| st.as_str().to_string()),
            trust_level: manifest.as_ref().map(|m| format!("L{}", m.trust_level)),
            degradations,
            decision_rounds: progress.iterations,
            decision_since_last_ms: progress.since_last_ms,
            loss: loss.clone(),
            actions: BeatActions {
                intents: j.intents,
                outcomes: j.outcomes,
                unwritten: j.unwritten,
                interrupted_at_boot: j.interrupted_at_boot,
                in_flight: j.in_flight,
            },
            probe_gaps: s.probe_on.then(crate::telemetry_probe::gaps_total),
            heads,
            stop_reason: stop_reason.map(str::to_string),
            capabilities: s.manifest.as_ref().and_then(|m| m.beat()),
            export: s.export.as_ref().map(|e| e.beat()),
        };
        let written = match &mut w.log {
            Some(log) => match log.append(record) {
                Ok(_) => true,
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "a heartbeat was not written");
                    false
                }
            },
            None => false,
        };
        if written {
            w.beats += 1;
            w.next_seq += 1;
        } else {
            w.unwritten += 1;
        }
        // telemetry_loss: on a change at most once a minute, unchanged once
        // an hour; the first beat signs the run's baseline
        let due = match &w.loss_row {
            None => true,
            Some((last, at)) => {
                (last != &loss && at.elapsed() >= LOSS_ROW_EVERY_CHANGED)
                    || at.elapsed() >= LOSS_ROW_EVERY_UNCHANGED
                    || kind == BeatKind::Stop
            }
        };
        if due {
            let previous = w.loss_row.as_ref().map(|(l, at)| (l.clone(), at.elapsed()));
            w.loss_row = Some((loss.clone(), Instant::now()));
            drop(w);
            sign_loss(s.audit.as_ref(), &s.run, &loss, previous, kind);
        }
    }
}

/// The signed `telemetry_loss` row: every stage's total since the run
/// started and what it lost since the last row.
fn sign_loss(
    audit: Option<&Arc<Mutex<AuditLog>>>,
    run: &str,
    loss: &[Option<u64>],
    previous: Option<(Vec<Option<u64>>, Duration)>,
    kind: BeatKind,
) {
    let names = nn_evidence::heartbeat::STAGE_NAMES;
    let mut any = false;
    let stages: Vec<serde_json::Value> = loss
        .iter()
        .enumerate()
        .map(|(i, total)| {
            let before = previous
                .as_ref()
                .and_then(|(p, _)| p.get(i).copied().flatten())
                .unwrap_or(0);
            let since = total.map(|t| t.saturating_sub(before));
            if since.is_some_and(|d| d > 0) {
                any = true;
            }
            serde_json::json!({
                "stage": i + 1,
                "name": names.get(i).copied().unwrap_or("?"),
                "total": total,
                "since_last_row": since,
            })
        })
        .collect();
    if any {
        warn!(
            stages = %serde_json::Value::from(stages.clone()),
            "telemetry loss since the last signed row (signed telemetry_loss)"
        );
    }
    let Some(log) = audit else {
        return;
    };
    let draft = AuditEntryDraft {
        op: TELEMETRY_LOSS_OP.to_string(),
        extra: serde_json::json!({
            "run": run,
            "stages": stages,
            "window_secs": previous.as_ref().map(|(_, d)| d.as_secs()),
            "at": match kind {
                BeatKind::Start => "start",
                BeatKind::Beat => "beat",
                BeatKind::Stop => "stop",
            },
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: if any { "detected" } else { "success" }.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "the telemetry_loss row was not written");
    }
}

/// The last beat's number in the chain at `path` (its active file, else its
/// newest archive); 0 for none.
/// A chain's head as a beat names it: file, bytes, hash.
type Head = (u64, u64, String);

/// The chain's last beat: its number (0: none), and the actions chain's
/// head it named.
fn last_beat(path: &Path) -> (u64, Option<Head>) {
    let mut files = vec![path.to_path_buf()];
    files.extend(
        crate::chainlog::archives_newest_first(path)
            .into_iter()
            .take(1),
    );
    for f in files {
        if let Some(found) = last_beat_in(&f) {
            return found;
        }
    }
    (0, None)
}

fn last_beat_in(path: &PathBuf) -> Option<(u64, Option<Head>)> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().rev().find_map(|l| {
        let v: serde_json::Value = serde_json::from_str(l).ok()?;
        if v.get("rotate").is_some() {
            return None;
        }
        let seq = v.get("seq")?.as_u64()?;
        let head = v.get("heads").and_then(|h| h.as_array()).and_then(|heads| {
            heads.iter().find_map(|h| {
                (h.get("chain")?.as_str()? == "actions").then_some(())?;
                Some((
                    h.get("file")?.as_u64()?,
                    h.get("bytes")?.as_u64()?,
                    h.get("hash")?.as_str()?.to_string(),
                ))
            })
        });
        Some((seq, head))
    })
}

/// `nn-admin heartbeat export`'s read (nn-evidence's).
pub use nn_evidence::heartbeat::tail_lines as export_lines;

#[cfg(test)]
mod tests {
    use super::*;

    fn sources() -> Sources {
        Sources {
            agent_id: [7; 16],
            run: "1234567890abcdef".into(),
            posture: crate::posture::PostureMachine::new(),
            ladder: None,
            manifest: None,
            bus: None,
            dispatch: None,
            journal: crate::response::journal::ActionJournal::memory(),
            audit: None,
            probe_on: false,
            export: None,
        }
    }

    /// Lot 276: stage 8 is the export's loss — `None` without an export,
    /// its count with one on.
    #[test]
    fn the_export_s_loss_is_stage_8() {
        let none = loss_now(&sources());
        assert_eq!(none.len(), 8);
        assert_eq!(none[7], None);
        let h =
            crate::export::ExportHandle::new(&crate::export::parse("enabled = true\nfile = on\n"))
                .unwrap();
        h.add_lost(3);
        let s = Sources {
            export: Some(h),
            ..sources()
        };
        let on = loss_now(&s);
        assert_eq!(on.len(), 8);
        assert_eq!(on[7], Some(3));
    }

    /// A start beat at the open, numbered beats after it continuing across
    /// a restart, a stop beat with its reason; the chain verifies, and the
    /// export gives its tail as on disk — the verifier's input.
    #[test]
    fn beats_are_numbered_chained_and_exported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat.jsonl");
        let key_path = dir.path().join("agent.sig.key");
        let key = || crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key().verifying_key();
        let hb = Heartbeat::open(
            &path,
            key(),
            Arc::new(crate::chainlog::NoProtection),
            false,
            sources(),
        );
        hb.beat(BeatKind::Beat, None);
        hb.stop("admin_shutdown");
        assert_eq!(hb.counts(), (3, 0));
        // the next run continues the numbers
        let hb = Heartbeat::open(
            &path,
            key(),
            Arc::new(crate::chainlog::NoProtection),
            false,
            sources(),
        );
        hb.beat(BeatKind::Beat, None);
        let lines = export_lines(&path, 10).unwrap();
        assert!(lines.len() >= 5, "{lines:?}");
        let beats: Vec<HeartbeatRecord> = lines
            .iter()
            .filter(|l| !l.starts_with("{\"rotate\""))
            .map(|l| {
                serde_json::from_str::<crate::chainlog::ChainLine<HeartbeatRecord>>(l)
                    .unwrap()
                    .payload
            })
            .collect();
        let seqs: Vec<u64> = beats.iter().map(|b| b.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
        let kinds: Vec<BeatKind> = beats.iter().map(|b| b.kind).collect();
        use BeatKind::*;
        assert_eq!(kinds, [Start, Beat, Stop, Start, Beat]);
        assert_eq!(beats[2].stop_reason.as_deref(), Some("admin_shutdown"));
        // stages 1 to 8 (lot 276: the export's)
        assert_eq!(beats[0].loss.len(), 8);
        // the verifier's check accepts the whole tail
        let raw: Vec<Vec<u8>> = lines.iter().map(|l| l.as_bytes().to_vec()).collect();
        let r = nn_evidence::heartbeat::check(
            Ok(&raw),
            &pk,
            None,
            chrono::Utc::now(),
            &nn_evidence::heartbeat::WatchConfig::default(),
        );
        assert!(r.alerts.is_empty(), "{r:?}");
        assert_eq!(r.state.unwrap().seq, 5);
        // the export's last two lines
        assert_eq!(export_lines(&path, 2).unwrap().len(), 2);
    }

    /// The `telemetry_loss` rows: the run's baseline at its first beat, none
    /// for a beat within the minute with nothing changed, one at the stop —
    /// signed in the audit log.
    #[test]
    fn telemetry_loss_rows_are_signed_at_the_start_and_the_stop() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("agent.sig.key");
        let key = || crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let audit_path = dir.path().join("audit.log");
        let audit = Arc::new(Mutex::new(
            crate::audit::AuditLog::open(&audit_path, key(), [1; 16]).unwrap(),
        ));
        let mut src = sources();
        src.audit = Some(Arc::clone(&audit));
        let hb = Heartbeat::open(
            &dir.path().join("heartbeat.jsonl"),
            key(),
            Arc::new(crate::chainlog::NoProtection),
            false,
            src,
        );
        hb.beat(BeatKind::Beat, None);
        hb.stop("sigterm");
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&audit_path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|r: &serde_json::Value| r["op"] == TELEMETRY_LOSS_OP)
            .collect();
        let at: Vec<&str> = rows
            .iter()
            .map(|r| r["extra"]["at"].as_str().unwrap())
            .collect();
        assert_eq!(at, ["start", "stop"], "{rows:#?}");
        assert_eq!(rows[0]["extra"]["stages"].as_array().unwrap().len(), 8);
        assert_eq!(rows[0]["extra"]["run"], "1234567890abcdef");
        // the beats name the audit chain's head
        let lines = export_lines(&dir.path().join("heartbeat.jsonl"), 10).unwrap();
        let last: crate::chainlog::ChainLine<HeartbeatRecord> =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        assert!(last
            .payload
            .heads
            .iter()
            .any(|h| h.chain == "audit" && h.seq.is_some()));
    }

    /// The last beat's head of the actions chain.
    fn actions_head(path: &Path) -> BeatHead {
        let lines = export_lines(path, 1).unwrap();
        let last: crate::chainlog::ChainLine<HeartbeatRecord> =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        last.payload
            .heads
            .into_iter()
            .find(|h| h.chain == "actions")
            .expect("the actions chain's head")
    }

    /// Review of #476: each beat names the actions chain's head — its
    /// position (the active file's number, its length) and its hash, as
    /// the journal has it; it grows with the chain.
    #[test]
    fn beats_name_the_actions_chain_s_head() {
        use crate::response::journal::{ActionIntent, ActionJournal, ActionResult};
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("agent.sig.key");
        let key = || crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let active = dir.path().join("actions.jsonl");
        let journal = ActionJournal::late();
        journal.bind(
            ActionJournal::open_log(
                &active,
                key(),
                crate::chainlog::RotationConfig {
                    size_cap_bytes: u64::MAX,
                    max_archives: 8,
                    file_mode: 0o600,
                },
                Arc::new(crate::chainlog::NoProtection),
            )
            .unwrap(),
            &active,
        );
        let act = |pid| {
            journal
                .intent(ActionIntent::named("test", "KillProcess", pid))
                .finish(ActionResult::Success, "Killed".into(), None)
        };
        act(1);
        let mut s = sources();
        s.journal = journal.clone();
        let path = dir.path().join("heartbeat.jsonl");
        let hb = Heartbeat::open(
            &path,
            key(),
            Arc::new(crate::chainlog::NoProtection),
            false,
            s,
        );
        let first = actions_head(&path);
        let (file, bytes, hash) = journal.head().unwrap();
        assert_eq!(
            (first.file, first.bytes, first.hash.clone()),
            (Some(file), Some(bytes), hash)
        );
        assert_eq!(bytes, std::fs::metadata(&active).unwrap().len());
        act(2);
        hb.beat(BeatKind::Beat, None);
        let second = actions_head(&path);
        assert_eq!(second.file, first.file);
        assert!(second.bytes > first.bytes, "{second:?} {first:?}");
        assert_ne!(second.hash, first.hash);
        assert!(!second.went_back(&first) && first.went_back(&second));
        assert_eq!(second.kept, Some(true), "the first beat's head still there");
        // the review of #476: the tail cut on the host, then rows appended
        // past the cut — the next beat says the head it named is gone
        let len = std::fs::metadata(&active).unwrap().len();
        let text = std::fs::read(&active).unwrap();
        let body = &text[..text.len() - 1];
        let cut = body.iter().rposition(|b| *b == b'\n').unwrap() + 1;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&active)
            .unwrap();
        f.set_len(cut as u64).unwrap();
        drop(f);
        let journal2 = ActionJournal::late();
        journal2.bind(
            ActionJournal::open_log(
                &active,
                key(),
                crate::chainlog::RotationConfig {
                    size_cap_bytes: u64::MAX,
                    max_archives: 8,
                    file_mode: 0o600,
                },
                Arc::new(crate::chainlog::NoProtection),
            )
            .unwrap(),
            &active,
        );
        for pid in 3..6 {
            journal2
                .intent(ActionIntent::named("test", "KillProcess", pid))
                .finish(ActionResult::Success, "Killed".into(), None);
        }
        assert!(
            std::fs::metadata(&active).unwrap().len() > len,
            "past the cut"
        );
        let mut s2 = sources();
        s2.journal = journal2;
        drop(hb);
        let hb = Heartbeat::open(
            &path,
            key(),
            Arc::new(crate::chainlog::NoProtection),
            false,
            s2,
        );
        let third = actions_head(&path);
        assert_eq!(third.kept, Some(false), "{third:?}");
        drop(hb);
    }

    /// The verifier end to end (`nn-admin heartbeat watch`'s check, its
    /// state file): beats on time are OK, the same chain again is OK with no
    /// new beat, an older copy of the chain is a replay.
    #[test]
    fn the_verifier_reads_the_chain_and_keeps_its_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat.jsonl");
        let key_path = dir.path().join("agent.sig.key");
        let key = || crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key().verifying_key();
        let hb = Heartbeat::open(
            &path,
            key(),
            Arc::new(crate::chainlog::NoProtection),
            false,
            sources(),
        );
        let old = dir.path().join("old.jsonl");
        std::fs::copy(&path, &old).unwrap();
        hb.beat(BeatKind::Beat, None);
        let w = nn_admin::heartbeat::Watch {
            pubkey: pk,
            source: nn_admin::heartbeat::Source::File(path.clone()),
            state: dir.path().join("state/watch.json"),
            every: None,
            cfg: nn_evidence::heartbeat::WatchConfig::default(),
            reanchor: false,
        };
        let r = nn_admin::heartbeat::check_once(&w).unwrap();
        assert!(r.anchored && r.alerts.is_empty(), "{r:?}");
        assert!(w.state.exists(), "the state is kept");
        hb.beat(BeatKind::Beat, None);
        let r = nn_admin::heartbeat::check_once(&w).unwrap();
        assert!(
            !r.anchored && r.alerts.is_empty() && r.new_beats == 1,
            "{r:?}"
        );
        let r = nn_admin::heartbeat::check_once(&w).unwrap();
        assert!(r.alerts.is_empty() && r.new_beats == 0, "{r:?}");
        let replay = nn_admin::heartbeat::Watch {
            source: nn_admin::heartbeat::Source::File(old),
            ..w.clone()
        };
        let r = nn_admin::heartbeat::check_once(&replay).unwrap();
        assert_eq!(r.exit_code(), 12, "{r:?}");
    }
}
