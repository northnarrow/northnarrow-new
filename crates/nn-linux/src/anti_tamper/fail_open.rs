//! Userland side of the deny hooks' fail-open counters (`DENY_FAIL_OPEN`
//! per-CPU map, `common::fail_open`; lab PR 215, capability C23).
//!
//! A deny hook that cannot read what it needs to decide lets the
//! operation through and bumps its slot. A sampler sums the per-CPU
//! values every [`SAMPLE_SECS`], keeps the totals for `nn-admin status`
//! (the signed telemetry), logs every increase at WARN with the hook's
//! name and writes a signed [`AUDIT_OP`] entry: at the first increase of a
//! hook, then at most once per hook per [`AUDIT_WINDOW_SECS`], each entry
//! carrying every fail-open since the previous one, so none goes
//! unrecorded. The posture is not raised: a fail-open says that a hook
//! could not decide, not that someone tried something, and the operation
//! it let through is judged by the other sensors like any other.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::late_audit::{AuditHandle, LateAudit};

use aya::maps::{MapData, PerCpuArray};
use aya::Ebpf;
use common::fail_open::{FAIL_OPEN_HOOKS, FAIL_OPEN_SLOTS};
use tracing::{debug, info, warn};

/// Sampling period.
pub const SAMPLE_SECS: u64 = 10;
/// Map name in the eBPF object.
pub const MAP_NAME: &str = "DENY_FAIL_OPEN";
/// Audit op of a deny hook that let operations through undecided.
pub const AUDIT_OP: &str = "deny_fail_open";
/// At most one audit entry per hook per window after its first one.
pub const AUDIT_WINDOW_SECS: u64 = 600;

const SLOTS: usize = FAIL_OPEN_SLOTS as usize;

static TOTALS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// The counters are read (the map was found and the sampler runs).
static ARMED: AtomicBool = AtomicBool::new(false);

/// What [`install`] gives the start (R11c, lab PR 264): the sampler's
/// audit log, bound once it exists (the sampler starts earlier, with the
/// eBPF object), and why the counters could not be armed, attested at the
/// binding. They were process-wide statics that `set_audit_log` filled.
#[derive(Clone, Debug, Default)]
pub struct FailOpen {
    audit: LateAudit,
    install_failure: Option<String>,
}

impl FailOpen {
    /// Hand the signed audit log to the sampler (the start's late binding,
    /// once it exists): a failed install is signed now.
    pub fn bind_audit_log(&self, log: Option<AuditHandle>) {
        if let Some(l) = log {
            if let Some(detail) = &self.install_failure {
                append(
                    &l,
                    crate::self_integrity::AUDIT_OP,
                    serde_json::json!({ "kind": "subsystem_degraded", "detail": detail, "at_boot": true }),
                );
            }
            self.audit.bind(Some(l));
        }
    }
}

fn append(log: &AuditHandle, op: &str, extra: serde_json::Value) {
    let draft = crate::audit::AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = format!("{e:#}"),
            op, "deny fail-open audit entry failed"
        );
    }
}

/// The `extra` of a [`AUDIT_OP`] entry.
fn audit_extra(hook: &str, since_last_entry: u64, total: u64) -> serde_json::Value {
    serde_json::json!({
        "hook": hook,
        "fail_open_since_last_entry": since_last_entry,
        "total": total,
    })
}

/// Cumulative fail-opens per hook, `(hook, count)`, every slot.
pub fn snapshot() -> Vec<(&'static str, u64)> {
    FAIL_OPEN_HOOKS
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, TOTALS[i].load(Ordering::Relaxed)))
        .collect()
}

/// Only the hooks that failed open.
pub fn snapshot_nonzero() -> Vec<(String, u64)> {
    snapshot()
        .into_iter()
        .filter(|(_, c)| *c > 0)
        .map(|(n, c)| (n.to_string(), c))
        .collect()
}

/// Sum over every hook; `None` while the counters are not read (the eBPF
/// object exports no `DENY_FAIL_OPEN`): "not counted", never a 0.
pub fn total() -> Option<u64> {
    ARMED
        .load(Ordering::Relaxed)
        .then(|| TOTALS.iter().map(|a| a.load(Ordering::Relaxed)).sum())
}

/// Sum the per-CPU values of every slot; a slot that cannot be read is
/// `None` (it keeps its previous total, as the ring-drop counters do).
fn read_map(map: &PerCpuArray<MapData, u64>) -> Vec<Option<u64>> {
    (0..FAIL_OPEN_SLOTS)
        .map(|slot| {
            map.get(&slot, 0)
                .ok()
                .map(|per_cpu| per_cpu.iter().sum::<u64>())
        })
        .collect()
}

/// This sample's totals: a slot that could not be read keeps its previous
/// total, and a counter never goes back (the map is per boot; a smaller
/// value would only be a read of another object).
fn merge_sample(prev: &[u64], now: &[Option<u64>]) -> Vec<u64> {
    prev.iter()
        .zip(now.iter())
        .map(|(&p, n)| n.map_or(p, |v| v.max(p)))
        .collect()
}

/// When a hook's fail-opens are written to the signed audit log.
#[derive(Debug, Default, Clone)]
struct AuditPacer {
    last_entry: Option<Instant>,
    recorded_total: u64,
}

impl AuditPacer {
    /// The fail-opens to record now — every one since the previous entry —
    /// or `None`: nothing new, or the window since the previous entry is
    /// still open (they wait for the first sample after it).
    fn due(&mut self, total: u64, now: Instant) -> Option<u64> {
        if total <= self.recorded_total {
            return None;
        }
        if self
            .last_entry
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(AUDIT_WINDOW_SECS))
        {
            return None;
        }
        let since = total - self.recorded_total;
        self.recorded_total = total;
        self.last_entry = Some(now);
        Some(since)
    }
}

/// One sample: the new totals published, a WARN per hook that failed
/// open since the previous sample, and the audit entries due.
fn apply_sample(
    prev: &[u64],
    cur: &[u64],
    pacers: &mut [AuditPacer],
    now: Instant,
) -> Vec<(&'static str, u64, u64)> {
    let mut entries = Vec::new();
    for (i, (&n, &p)) in cur.iter().zip(prev.iter()).enumerate() {
        TOTALS[i].store(n, Ordering::Relaxed);
        if n > p {
            warn!(
                hook = FAIL_OPEN_HOOKS[i],
                fail_open_since_last_sample = n - p,
                total = n,
                "deny hook FAILED OPEN — a kernel read it needed failed, and it let the \
                 operation through undecided"
            );
        }
        if let Some(since) = pacers[i].due(n, now) {
            entries.push((FAIL_OPEN_HOOKS[i], since, n));
        }
    }
    entries
}

/// Take the `DENY_FAIL_OPEN` map from the loaded object and start the
/// sampler. A missing or mistyped map is a WARN and, once the audit log is
/// bound ([`FailOpen::bind_audit_log`]), a signed `subsystem_degraded`
/// (fail-opens then go uncounted, and the status says "not counted").
pub fn install(ebpf: &mut Ebpf) -> FailOpen {
    let failed = |detail: String| FailOpen {
        install_failure: Some(detail),
        ..FailOpen::default()
    };
    let Some(map) = ebpf.take_map(MAP_NAME) else {
        warn!(
            map = MAP_NAME,
            "deny fail-open counters not exported by the eBPF object — fail-opens will not be counted"
        );
        return failed(format!(
            "deny fail-open counters unavailable: map {MAP_NAME} not exported by the eBPF \
             object; a deny hook that lets an operation through undecided is not counted"
        ));
    };
    let map: PerCpuArray<MapData, u64> = match PerCpuArray::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, map = MAP_NAME, "deny fail-open map has an unexpected type — fail-opens will not be counted");
            return failed(format!(
                "deny fail-open counters unavailable: map {MAP_NAME} has an unexpected type \
                 ({e}); a deny hook that lets an operation through undecided is not counted"
            ));
        }
    };
    let bindings = FailOpen::default();
    let audit = bindings.audit.clone();
    ARMED.store(true, Ordering::Relaxed);
    info!(
        hooks = FAIL_OPEN_SLOTS,
        every_secs = SAMPLE_SECS,
        "deny fail-open counters armed"
    );
    tokio::spawn(async move {
        let mut prev = vec![0u64; SLOTS];
        let mut pacers = vec![AuditPacer::default(); SLOTS];
        loop {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
            let cur = merge_sample(&prev, &read_map(&map));
            let entries = apply_sample(&prev, &cur, &mut pacers, Instant::now());
            if let Some(log) = audit.get() {
                for (hook, since, total) in entries {
                    append(log, AUDIT_OP, audit_extra(hook, since, total));
                }
            } else if !entries.is_empty() {
                // Before the audit log exists: the pacers already counted
                // these as recorded; put them back so the first entry
                // after it opens carries them.
                for (hook, since, _) in entries {
                    if let Some(i) = FAIL_OPEN_HOOKS.iter().position(|h| *h == hook) {
                        pacers[i].recorded_total -= since;
                        pacers[i].last_entry = None;
                    }
                }
            }
            prev = cur;
            debug!(total = total(), "deny fail-open sample");
        }
    });
    bindings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every deny hook the agent attaches, the optional ones and the `bpf`
    /// observer (it refuses link handles) has a slot, and nothing else.
    #[test]
    fn every_deny_hook_has_a_fail_open_slot() {
        let mut hooks: Vec<&str> = super::super::DENY_HOOKS.to_vec();
        hooks.extend(super::super::OPTIONAL_DENY_HOOKS);
        hooks.push(super::super::bpf_defense::OBSERVE_HOOK);
        hooks.sort_unstable();
        let mut slots = FAIL_OPEN_HOOKS.to_vec();
        slots.sort_unstable();
        assert_eq!(hooks, slots);
    }

    /// A slot that could not be read keeps its total; a counter never
    /// goes back.
    #[test]
    fn a_read_error_keeps_the_previous_total() {
        assert_eq!(
            merge_sample(&[3, 5, 0], &[None, Some(7), Some(0)]),
            vec![3, 7, 0]
        );
        assert_eq!(merge_sample(&[9], &[Some(2)]), vec![9]);
    }

    /// The first fail-open of a hook is recorded at once; later ones wait
    /// for the window and are then recorded together, none lost.
    #[test]
    fn every_fail_open_reaches_the_audit_log_paced() {
        let t0 = Instant::now();
        let mut p = AuditPacer::default();
        assert_eq!(p.due(0, t0), None);
        assert_eq!(p.due(1, t0), Some(1));
        assert_eq!(p.due(1, t0 + Duration::from_secs(10)), None);
        assert_eq!(p.due(4, t0 + Duration::from_secs(20)), None);
        assert_eq!(p.due(6, t0 + Duration::from_secs(590)), None);
        assert_eq!(
            p.due(6, t0 + Duration::from_secs(AUDIT_WINDOW_SECS)),
            Some(5)
        );
        assert_eq!(
            p.due(6, t0 + Duration::from_secs(2 * AUDIT_WINDOW_SECS)),
            None
        );
    }

    /// A sample publishes the totals and names the hooks to record.
    #[test]
    fn a_sample_reports_the_hooks_that_failed_open() {
        let now = Instant::now();
        let prev = vec![0u64; SLOTS];
        let mut cur = prev.clone();
        cur[common::fail_open::hook::FILE_OPEN as usize] = 2;
        cur[common::fail_open::hook::BPF as usize] = 1;
        let mut pacers = vec![AuditPacer::default(); SLOTS];
        let entries = apply_sample(&prev, &cur, &mut pacers, now);
        assert_eq!(entries, vec![("file_open", 2, 2), ("bpf", 1, 1)]);
        assert_eq!(
            snapshot_nonzero(),
            vec![("file_open".to_string(), 2), ("bpf".to_string(), 1)]
        );
        assert!(apply_sample(&cur, &cur, &mut pacers, now).is_empty());
        // reset for the other tests of this process
        apply_sample(&cur, &prev, &mut pacers, now);
        assert!(snapshot_nonzero().is_empty());
    }

    #[test]
    fn the_audit_entry_names_the_hook_and_the_counts() {
        assert_eq!(
            audit_extra("task_kill", 3, 10),
            serde_json::json!({ "hook": "task_kill", "fail_open_since_last_entry": 3, "total": 10 })
        );
    }

    /// Not armed (no map in the object): no total, rather than a 0.
    #[test]
    fn no_total_until_the_counters_are_read() {
        if !ARMED.load(Ordering::Relaxed) {
            assert_eq!(total(), None);
        }
    }
}
