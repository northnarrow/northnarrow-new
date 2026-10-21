//! Userland side of the per-ring drop counters (`RING_DROPS` per-CPU map,
//! `common::ring_drops`). A sampler task sums the per-CPU values every
//! [`SAMPLE_SECS`], keeps the totals in process-wide atomics (read by the
//! admin socket for `nn-admin status`) and logs every increase at WARN
//! with the ring's name — a dropped event is a blind spot the operator
//! must see, not a silent counter.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use aya::maps::{MapData, PerCpuArray};
use aya::Ebpf;
use common::ring_drops::{ring_slot, RING_DROP_NAMES, RING_DROP_SLOTS};
use tracing::{debug, info, warn};

/// Sampling period.
pub const SAMPLE_SECS: u64 = 10;
/// Map name in the eBPF object.
pub const MAP_NAME: &str = "RING_DROPS";

/// Audit op of a visibility loss (adversarial finding: a flood that fills a
/// ring and hides the next event must not be a journal line only).
pub const AUDIT_OP: &str = "ringbuf_drop";
/// At most one audit entry per ring per window (the WARN stays per sample).
pub const AUDIT_WINDOW_SECS: u64 = 600;

static AUDIT_LOG: OnceLock<Arc<parking_lot::Mutex<crate::audit::AuditLog>>> = OnceLock::new();

/// Hand the signed audit log to the sampler (from `main`, once it exists;
/// the sampler starts earlier, with the eBPF object).
pub fn set_audit_log(log: Option<Arc<parking_lot::Mutex<crate::audit::AuditLog>>>) {
    if let Some(l) = log {
        if let Some(detail) = INSTALL_FAILURE.get() {
            attest_install_failure(&l, detail);
        }
        let _ = AUDIT_LOG.set(l);
    }
}

fn audit_drop(ring: &str, dropped: u64, total: u64) {
    let Some(log) = AUDIT_LOG.get() else { return };
    let draft = crate::audit::AuditEntryDraft {
        op: AUDIT_OP.to_string(),
        extra: serde_json::json!({ "ring": ring, "dropped_since_last_sample": dropped, "total": total }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = format!("{e:#}"), "ring-drop audit entry failed");
    }
}

static TOTALS: [AtomicU64; RING_DROP_SLOTS as usize] =
    [const { AtomicU64::new(0) }; RING_DROP_SLOTS as usize];

/// Cumulative drops per ring, `(name, count)`, every slot.
pub fn snapshot() -> Vec<(&'static str, u64)> {
    RING_DROP_NAMES
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, TOTALS[i].load(Ordering::Relaxed)))
        .collect()
}

/// Only the rings that dropped something.
pub fn snapshot_nonzero() -> Vec<(String, u64)> {
    snapshot()
        .into_iter()
        .filter(|(_, c)| *c > 0)
        .map(|(n, c)| (n.to_string(), c))
        .collect()
}

/// Sum over every ring.
pub fn total() -> u64 {
    TOTALS.iter().map(|a| a.load(Ordering::Relaxed)).sum()
}

/// Sum the per-CPU values of every slot. External audit SNS-009: a failed
/// read is `None`, not zero (zero rewrote the total shown by `nn-admin
/// status` and skewed the next sample's delta).
fn read_map(map: &PerCpuArray<MapData, u64>) -> Vec<Option<u64>> {
    (0..RING_DROP_SLOTS)
        .map(|slot| {
            map.get(&slot, 0)
                .ok()
                .map(|per_cpu| per_cpu.iter().sum::<u64>())
        })
        .collect()
}

/// External audit SNS-009: this sample's totals. A slot that could not be
/// read keeps its previous total (WARN once until it reads again).
fn merge_sample(prev: &[u64], now: &[Option<u64>], failing: &mut [bool]) -> Vec<u64> {
    prev.iter()
        .zip(now.iter())
        .enumerate()
        .map(|(i, (&p, n))| match n {
            Some(v) => {
                failing[i] = false;
                *v
            }
            None => {
                if !failing[i] {
                    failing[i] = true;
                    warn!(
                        ring = RING_DROP_NAMES[i],
                        "ring-drop counter unreadable — keeping the previous total"
                    );
                }
                p
            }
        })
        .collect()
}

/// External audit SNS-009: the rings whose loss hides security evidence.
/// A drop there raises `TriggerType::TelemetryLoss` (ALERTED).
pub const SECURITY_RINGS: [u32; 10] = [
    ring_slot::EXEC,
    ring_slot::FS_PROTECT,
    ring_slot::OPEN_SENSOR,
    ring_slot::FIM,
    ring_slot::MODULE_LOAD,
    ring_slot::BPF,
    // External audit EBPF-009: a refused write-then-close marker hides an
    // in-place modification of a watched file.
    ring_slot::FIM_DIRTY_FULL,
    // External audit EBPF-017: anti-tamper task denials (signals, ptrace
    // on a protected pid) the kernel held back over its per-CPU budget.
    // The first denial already raised the decisive trigger; a burst past
    // the budget is a loss of evidence the operator must see.
    ring_slot::TASK_DENIAL_RATE,
    // Lab PR 223: an exec quarantine candidate the ring could not hold
    // ran unstopped and unscanned.
    ring_slot::EXECQ,
    // Lab PR 226: an exec policy report lost — a deny (or an environment
    // or mapping finding) without its record.
    ring_slot::EXECPOL,
];

/// Events a security ring may lose within one sample before the posture
/// moves. A flood that hides an event loses many more; a stray reservation
/// failure under load does not alert. Bursts beyond it from a package
/// transaction or a trusted-installer window are exempt (review 45 measured
/// 1 261 and 4 597 drops on a `daemon-reload` and an install burst).
pub const TELEMETRY_LOSS_THRESHOLD: u64 = 64;

/// `(ring, dropped this sample)` for the security rings above the threshold.
fn security_losses(prev: &[u64], cur: &[u64]) -> Vec<(&'static str, u64)> {
    SECURITY_RINGS
        .iter()
        .map(|&slot| slot as usize)
        .filter_map(|i| {
            let d = cur[i].saturating_sub(prev[i]);
            (d > TELEMETRY_LOSS_THRESHOLD).then_some((RING_DROP_NAMES[i], d))
        })
        .collect()
}

struct PostureSink {
    posture: crate::posture::PostureMachine,
    installer: Option<Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>>,
}

static POSTURE: OnceLock<PostureSink> = OnceLock::new();

/// Hand the posture machine (and the trusted-installer window) to the
/// sampler, so a security ring that loses events raises ALERTED.
pub fn set_posture(
    posture: crate::posture::PostureMachine,
    installer: Option<Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>>,
) {
    let _ = POSTURE.set(PostureSink { posture, installer });
}

/// Package managers whose run, as root, is a package transaction. Their
/// bursts (maintainer scripts, unit reloads) legitimately overflow rings.
const PACKAGE_MANAGER_EXES: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/aptitude",
    "/usr/bin/dpkg",
    "/usr/bin/rpm",
    "/usr/bin/microdnf",
    "/usr/bin/zypper",
];

/// Package managers that are interpreter scripts (`/proc/<pid>/exe` is the
/// interpreter): matched by `argv[1]`, root processes only.
const PACKAGE_MANAGER_SCRIPTS: &[&str] = &[
    "/usr/bin/dnf",
    "/usr/bin/dnf-3",
    "/usr/bin/yum",
    "/usr/bin/unattended-upgrade",
];

/// A package transaction is running: a root process (effective uid 0) runs
/// a package manager. An unprivileged user running `dpkg -l` does not
/// count, so a user cannot open the exemption for their own flood.
fn package_transaction_running(proc_root: &std::path::Path) -> bool {
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return false;
    };
    dir.flatten().any(|e| {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            return false;
        };
        let base = proc_root.join(pid);
        let root = std::fs::read_to_string(base.join("status"))
            .ok()
            .and_then(|st| {
                st.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|u| u.split_whitespace().nth(1).map(|e| e == "0"))
            })
            .unwrap_or(false);
        if !root {
            return false;
        }
        let exe = std::fs::read_link(base.join("exe")).unwrap_or_default();
        if PACKAGE_MANAGER_EXES
            .iter()
            .any(|p| exe == std::path::Path::new(p))
        {
            return true;
        }
        std::fs::read(base.join("cmdline"))
            .ok()
            .and_then(|c| {
                c.split(|b| *b == 0)
                    .nth(1)
                    .map(|a| PACKAGE_MANAGER_SCRIPTS.iter().any(|p| a == p.as_bytes()))
            })
            .unwrap_or(false)
    })
}

/// External audit SNS-009: security rings lost events — raise
/// `TelemetryLoss` (ALERTED), except during a trusted-installer window or a
/// package transaction. The signed `ringbuf_drop` entry is written anyway.
fn raise_telemetry_loss(lost: &[(&'static str, u64)]) {
    let Some(sink) = POSTURE.get() else { return };
    let what = lost
        .iter()
        .map(|(r, d)| format!("{r} {d}"))
        .collect::<Vec<_>>()
        .join(", ");
    if sink.installer.as_ref().is_some_and(|i| i.is_window_open()) {
        info!(lost = %what, "ring drops during a trusted-installer window — posture not raised");
        return;
    }
    if package_transaction_running(std::path::Path::new("/proc")) {
        info!(lost = %what, "ring drops during a package transaction — posture not raised");
        return;
    }
    let reason = format!("security ring events dropped in {SAMPLE_SECS} s: {what}");
    if let Some(state) = sink
        .posture
        .raise_signal(common::posture_types::TriggerType::TelemetryLoss, &reason)
    {
        warn!(
            state = %state.kind(),
            trigger = "TelemetryLoss",
            lost = %what,
            "POSTURE TRANSITION"
        );
    }
}

/// External audit SNS-009: why the counters could not be armed, attested
/// in the signed chain once the audit log exists.
static INSTALL_FAILURE: OnceLock<String> = OnceLock::new();

fn attest_install_failure(log: &Arc<parking_lot::Mutex<crate::audit::AuditLog>>, detail: &str) {
    let draft = crate::audit::AuditEntryDraft {
        op: crate::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({ "kind": "subsystem_degraded", "detail": detail, "at_boot": true }),
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
            "attesting the ring-drop counters' absence failed"
        );
    }
}

/// Take the `RING_DROPS` map from the loaded object and start the
/// sampler. A missing or mistyped map is a WARN and, once the audit log is
/// set, a signed `subsystem_degraded` (drops then go uncounted).
pub fn install(ebpf: &mut Ebpf) {
    let Some(map) = ebpf.take_map(MAP_NAME) else {
        warn!(
            map = MAP_NAME,
            "ring-drop counters not exported by the eBPF object — drops will not be counted"
        );
        let _ = INSTALL_FAILURE.set(format!(
            "ring-drop counters unavailable: map {MAP_NAME} not exported by the eBPF object; ring drops are not counted"
        ));
        return;
    };
    let map: PerCpuArray<MapData, u64> = match PerCpuArray::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, map = MAP_NAME, "ring-drop map has an unexpected type — drops will not be counted");
            let _ = INSTALL_FAILURE.set(format!(
                "ring-drop counters unavailable: map {MAP_NAME} has an unexpected type ({e}); ring drops are not counted"
            ));
            return;
        }
    };
    info!(
        rings = RING_DROP_SLOTS,
        every_secs = SAMPLE_SECS,
        "ring-drop counters armed"
    );
    tokio::spawn(async move {
        let mut prev = vec![0u64; RING_DROP_SLOTS as usize];
        let mut failing = vec![false; RING_DROP_SLOTS as usize];
        let mut last_audit: Vec<Option<Instant>> = vec![None; RING_DROP_SLOTS as usize];
        loop {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
            let now = merge_sample(&prev, &read_map(&map), &mut failing);
            for (i, (&n, &p)) in now.iter().zip(prev.iter()).enumerate() {
                TOTALS[i].store(n, Ordering::Relaxed);
                if n > p {
                    let due = last_audit[i]
                        .map(|t| t.elapsed() >= Duration::from_secs(AUDIT_WINDOW_SECS))
                        .unwrap_or(true);
                    if due {
                        last_audit[i] = Some(Instant::now());
                        audit_drop(RING_DROP_NAMES[i], n - p, n);
                    }
                    warn!(
                        ring = RING_DROP_NAMES[i],
                        dropped_since_last_sample = n - p,
                        total = n,
                        "ring-buffer events DROPPED — the consumer fell behind; events of this sensor were lost"
                    );
                }
            }
            let lost = security_losses(&prev, &now);
            if !lost.is_empty() {
                raise_telemetry_loss(&lost);
            }
            prev = now;
            debug!(total = total(), "ring-drop sample");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_names_match_slots_and_nonzero_filters() {
        let s = snapshot();
        assert_eq!(s.len(), RING_DROP_SLOTS as usize);
        assert_eq!(s[0].0, "exec");
        assert_eq!(s[10].0, "dns");
        assert_eq!(s[15].0, "fim_dirty_full");
        assert_eq!(s[17].0, "io_uring_rate");
        assert_eq!(s[18].0, "task_denial_rate");
        // totals start at zero in a fresh process
        assert!(snapshot_nonzero().is_empty());
        assert_eq!(total(), 0);
    }

    /// External audit SNS-009: an unreadable slot keeps its previous total
    /// (it was read as zero), and reads again once the map answers.
    #[test]
    fn read_error_keeps_previous_total() {
        let mut failing = vec![false; 3];
        let prev = [10, 20, 30];
        let cur = merge_sample(&prev, &[Some(12), None, Some(30)], &mut failing);
        assert_eq!(cur, vec![12, 20, 30]);
        assert_eq!(failing, vec![false, true, false]);
        let next = merge_sample(&cur, &[Some(12), Some(25), Some(31)], &mut failing);
        assert_eq!(next, vec![12, 25, 31]);
        assert_eq!(failing, vec![false, false, false]);
    }

    /// External audit SNS-009: only a security ring above the threshold
    /// within one sample counts as telemetry loss.
    #[test]
    fn security_ring_losses_above_threshold_only() {
        let slots = RING_DROP_SLOTS as usize;
        let prev = vec![100u64; slots];
        let mut cur = prev.clone();
        cur[ring_slot::EXEC as usize] += TELEMETRY_LOSS_THRESHOLD + 1;
        cur[ring_slot::FS_PROTECT as usize] += TELEMETRY_LOSS_THRESHOLD;
        cur[ring_slot::DNS as usize] += 10_000;
        assert_eq!(
            security_losses(&prev, &cur),
            vec![("exec", TELEMETRY_LOSS_THRESHOLD + 1)]
        );
        assert!(security_losses(&prev, &prev).is_empty());
    }

    /// External audit EBPF-017: task denials held back over the kernel's
    /// budget are a security loss, like a full `fs_protect` ring.
    #[test]
    fn task_denials_over_budget_are_a_security_loss() {
        let slots = RING_DROP_SLOTS as usize;
        let prev = vec![0u64; slots];
        let mut cur = prev.clone();
        cur[ring_slot::TASK_DENIAL_RATE as usize] = 4_500;
        assert_eq!(
            security_losses(&prev, &cur),
            vec![("task_denial_rate", 4_500)]
        );
    }

    fn fake_proc(root: &std::path::Path, pid: u32, euid: u32, exe: &str, cmdline: &[&str]) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("status"),
            format!("Name:\tx\nUid:\t{euid}\t{euid}\t{euid}\t{euid}\n"),
        )
        .unwrap();
        std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
        let mut c = cmdline.join("\0").into_bytes();
        c.push(0);
        std::fs::write(d.join("cmdline"), c).unwrap();
    }

    /// External audit SNS-009: a root package manager opens the exemption;
    /// the same binary run by a user does not.
    #[test]
    fn package_transaction_needs_a_root_package_manager() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        fake_proc(root, 100, 1000, "/usr/bin/dpkg", &["dpkg", "-l"]);
        fake_proc(root, 101, 0, "/usr/bin/bash", &["bash"]);
        std::fs::create_dir(root.join("self")).unwrap();
        assert!(!package_transaction_running(root));

        fake_proc(
            root,
            102,
            0,
            "/usr/bin/python3.12",
            &["/usr/bin/python3", "/usr/bin/unattended-upgrade"],
        );
        assert!(package_transaction_running(root));

        let tmp2 = tempfile::TempDir::new().unwrap();
        fake_proc(
            tmp2.path(),
            200,
            0,
            "/usr/bin/dpkg",
            &["/usr/bin/dpkg", "--configure", "-a"],
        );
        assert!(package_transaction_running(tmp2.path()));
    }
}
