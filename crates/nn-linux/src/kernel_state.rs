//! Lot 280b: the kernel's state the agent's hooks depend on and no hook of
//! its own sees change — read every [`PERIOD`] by the kernel-state round.
//!
//! * The taint flags (`/proc/sys/kernel/tainted`) and the livepatches
//!   (`/sys/kernel/livepatch`): a module that is not the distribution's,
//!   one loaded by force or unsigned, a livepatch (which replaces kernel
//!   functions, those a hook is attached to included) changes the code the
//!   hooks run beside. [`kernel_code`] is the capability manifest's entry
//!   (read at each of its builds: a change is a signed revision); a flag of
//!   `common::kernel_taint::CODE_ENTRY` that appears while the agent runs
//!   is a signed detection here (`FsProtectOperation::KernelTaint`:
//!   NN-L-AT-001, Critical for an unsigned or forced module, High for the
//!   rest) — not a refusal, so no posture trigger (the module-load sensor's
//!   rules judge the load itself).
//! * The root cgroup's `cgroup/sysctl` programs (lot 280a's residual): a
//!   program not the agent's, attached to the root after the judge, runs
//!   after it and may rewrite the value it judged. The `bpf` LSM hook
//!   refuses such an attach outside a window; one found there anyway (made
//!   inside a window, or before the agent's start) is a signed High
//!   detection (`FsProtectOperation::SysctlRootProg`), once per program;
//!   a root the attach no longer finds as it left it (our program gone, the
//!   mode no longer multi) is a signed degradation while it holds. Lot 304:
//!   one whose loader proves it a known system program
//!   ([`crate::known_system_prog`]: systemd-networkd's `sysctl_monitor`) is
//!   signed Low with that proof instead.
//!
//! * Lot 290: the light cross-view of the host's BPF programs and links
//!   ([`crate::bpf_crossview`]): an object the `bpf` hook never saw loading
//!   — present at the start (the baseline, signed once) or appearing later
//!   (a signed High) — with its type, name, tag and attach point.
//!
//! The detections go through the bus as the `fs_protect` source's events
//! (the kernel's refusals' source): judged, signed and counted like them.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use common::kernel_taint::new_code_entry;
use nn_core::contract::manifest::KernelCode;
use nn_model::{Event, FsProtectOperation};
use tracing::{info, warn};

use crate::sensors::bus::BusSender;

/// How often the round reads the kernel's state.
pub const PERIOD: Duration = Duration::from_secs(5);
/// The taint mask.
pub const TAINTED: &str = "/proc/sys/kernel/tainted";
/// The livepatches' directory.
pub const LIVEPATCH_DIR: &str = "/sys/kernel/livepatch";
/// The degradation's source while the root is not as the attach left it.
pub const ROOT_DEGRADATION: &str = "sysctl_judge_root";

/// The taint mask under `root` (`/` on the host, a directory in the
/// tests).
pub fn tainted(root: &Path) -> Result<u64, String> {
    let path = root.join(TAINTED.trim_start_matches('/'));
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{TAINTED}: {e}"))?;
    text.trim()
        .parse::<u64>()
        .map_err(|_| format!("{TAINTED} reads {:?}, not an integer", text.trim()))
}

/// Each livepatch under `root` and its state, sorted: `name`, `name
/// (disabled)`, `name (in transition)`.
pub fn livepatches(root: &Path) -> Vec<String> {
    let dir = root.join(LIVEPATCH_DIR.trim_start_matches('/'));
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let flag = |p: &Path, f: &str| {
        std::fs::read_to_string(p.join(f))
            .ok()
            .map(|t| t.trim() == "1")
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let p = e.path();
            match (flag(&p, "enabled"), flag(&p, "transition")) {
                (_, Some(true)) => format!("{name} (in transition)"),
                (Some(false), _) => format!("{name} (disabled)"),
                (None, _) => format!("{name} (state unread)"),
                (Some(true), _) => name,
            }
        })
        .collect();
    out.sort();
    out
}

/// The capability manifest's entry: the taint mask, its letters, the
/// livepatches.
pub fn kernel_code(root: &Path) -> KernelCode {
    match tainted(root) {
        Ok(m) => KernelCode {
            tainted: Some(m),
            taint: common::kernel_taint::letters(m),
            livepatches: livepatches(root),
        },
        Err(e) => KernelCode {
            tainted: None,
            taint: e,
            livepatches: livepatches(root),
        },
    }
}

/// What the round keeps between two reads.
#[derive(Debug, Default)]
pub struct Watch {
    /// The taint mask as last read (`None` before the first read: the
    /// flags set before the agent's start are the manifest's, not news).
    pub tainted: Option<u64>,
    /// The foreign root programs already signed.
    pub reported: BTreeSet<u32>,
    /// The root's degradation in force.
    pub root_degraded: Option<String>,
}

/// One round's findings, the events to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// New flags of code entering the kernel, and the whole mask.
    Taint { new: u64, mask: u64 },
    /// A program not ours on the root's `cgroup/sysctl` slot.
    RootProgram(u32),
    /// Lot 304: one that is a known system program, its loader proven.
    KnownRootProgram(crate::known_system_prog::Known),
    /// Lot 290: the cross-view's finding.
    Bpf(crate::bpf_crossview::Finding),
}

impl Watch {
    /// One read of the taint mask: the new flags of code entering the
    /// kernel since the last read. The first read is the baseline; an
    /// unread mask keeps the last one (the manifest says it was not read).
    pub fn taint(&mut self, now: Result<u64, String>) -> Option<Finding> {
        let now = now.ok()?;
        let before = self.tainted.replace(now)?;
        let new = new_code_entry(before, now);
        (new != 0).then_some(Finding::Taint { new, mask: now })
    }

    /// One read of the root's report ([`crate::sysctl_cgroup::root_report`]):
    /// each program not ours not signed before — a known system program
    /// when `known` proves it one (lot 304), else a program not ours; the
    /// root's degradation set or cleared (`Some(Some(line))` set,
    /// `Some(None)` cleared, `None` unchanged).
    pub fn root(
        &mut self,
        report: Result<Option<Vec<u32>>, String>,
        known: &dyn Fn(u32) -> Result<crate::known_system_prog::Known, String>,
    ) -> (Vec<Finding>, Option<Option<String>>) {
        match report {
            Ok(others) => {
                let found = others
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|id| self.reported.insert(*id))
                    .map(|id| match known(id) {
                        Ok(k) => Finding::KnownRootProgram(k),
                        Err(why) => {
                            info!(id, why = %why, "kernel state: a root cgroup/sysctl program not proven a known system program");
                            Finding::RootProgram(id)
                        }
                    })
                    .collect();
                let cleared = self.root_degraded.take().map(|_| None);
                (found, cleared)
            }
            Err(why) => {
                let line = format!(
                    "the root cgroup's cgroup/sysctl slot is not as the judge's attach left it: \
                     {why} — the guarded sysctls may not be judged on the kernel's copy"
                );
                if self.root_degraded.as_deref() == Some(line.as_str()) {
                    (Vec::new(), None)
                } else {
                    self.root_degraded = Some(line.clone());
                    (Vec::new(), Some(Some(line)))
                }
            }
        }
    }
}

/// `CLOCK_MONOTONIC` now, in ns (the kernel records' clock).
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid out-parameter for clock_gettime.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The event a finding is signed as (NN-L-AT-001): the kernel's own act,
/// no process behind it (pid 0, `kernel`) — but a known system program's
/// (lot 304), whose record names its loader (pid, uid; the root program's
/// name the loader's).
pub fn event_of(f: &Finding, timestamp_ns: u64) -> Event {
    let mut comm = "kernel".to_string();
    let (mut pid, mut uid) = (0, 0);
    let (operation, target_dev, target_ino) = match f {
        Finding::Taint { new, mask } => (FsProtectOperation::KernelTaint, *new, *mask),
        Finding::RootProgram(id) => (FsProtectOperation::SysctlRootProg, 0, u64::from(*id)),
        // lot 304: the loader proven, its pid, uid and name the record's
        Finding::KnownRootProgram(k) => {
            (pid, uid) = (k.pid, k.uid);
            comm = k.comm.clone();
            (
                FsProtectOperation::SysctlRootProg,
                common::bpf_prog_class::root_prog_known_dev(k.entry as u16, k.seen, k.link_id),
                u64::from(k.id),
            )
        }
        Finding::Bpf(b) => {
            use crate::bpf_crossview::Finding as B;
            let (op, o) = match b {
                B::Baseline(o) => (FsProtectOperation::BpfBaseline, o),
                B::Unseen(o) => (FsProtectOperation::BpfUnseen, o),
            };
            comm = common::bpf_prog_class::object_comm(&o.name, &o.attach);
            // lot 304: a known system program's loader, and the bit
            let known = match o.known {
                Some((p, u)) => {
                    (pid, uid) = (p, u);
                    common::bpf_prog_class::CROSSVIEW_KNOWN_BIT
                }
                None => 0,
            };
            (
                op,
                o.tag,
                common::bpf_prog_class::crossview_ino(o.is_link, o.early, o.object_type, o.id)
                    | known,
            )
        }
    };
    Event::FsProtectDenial {
        pid,
        uid,
        comm,
        target_dev,
        target_ino,
        operation,
        timestamp_ns,
    }
}

/// One round under `root` (`/`): the findings to sign. `known` tells a
/// root program that is a known system program (lot 304).
pub fn round(
    w: &mut Watch,
    root: &Path,
    known: &dyn Fn(u32) -> Result<crate::known_system_prog::Known, String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(f) = w.taint(tainted(root)) {
        warn!(finding = ?f, "kernel state: a taint flag of code entering the kernel appeared");
        out.push(f);
    }
    let (found, degradation) = w.root(crate::sysctl_cgroup::root_report(), known);
    for f in &found {
        match f {
            Finding::KnownRootProgram(k) => info!(
                finding = ?k,
                "kernel state: a known system program on the root cgroup's cgroup/sysctl slot, its loader proven"
            ),
            _ => {
                warn!(finding = ?f, "kernel state: a cgroup/sysctl program not the agent's on the root cgroup")
            }
        }
    }
    out.extend(found);
    match degradation {
        Some(Some(line)) => {
            warn!(detail = %line, "kernel state: the sysctl judge's root");
            crate::boot::degradation::withdraw(ROOT_DEGRADATION, &[]);
            if crate::boot::degradation::report(ROOT_DEGRADATION, &line) {
                crate::boot::degradation::flush();
            }
        }
        Some(None) => {
            info!("kernel state: the sysctl judge's root is as its attach left it again");
            crate::boot::degradation::withdraw(ROOT_DEGRADATION, &[]);
        }
        None => {}
    }
    out
}

/// Lot 290: one cross-view round — its findings, each logged; an error
/// is a signed degradation while it holds ([`crate::bpf_crossview::DEGRADATION`]).
pub fn crossview_round(
    cross: &mut crate::bpf_crossview::CrossView,
    failing: &mut Option<String>,
    agent_start: Option<u64>,
) -> Vec<Finding> {
    use crate::bpf_crossview::DEGRADATION;
    match cross.round() {
        Ok(mut found) => {
            // lot 304: a baseline program a known system program's loader
            // is proven to hold (PID 1's restrict_filesystems)
            mark_known_baselines(&mut found, &|id, link| {
                crate::known_system_prog::judge_on_host(
                    id,
                    link,
                    cross.watch.program(id).as_ref(),
                    agent_start,
                    None,
                )
            });
            if failing.take().is_some() {
                info!("kernel state: the BPF cross-view runs again");
                crate::boot::degradation::withdraw(DEGRADATION, &[]);
            }
            for f in &found {
                warn!(finding = ?f, "kernel state: a BPF object the bpf hook never saw loading");
            }
            found.into_iter().map(Finding::Bpf).collect()
        }
        Err(why) => {
            let line = format!(
                "the BPF cross-view could not enumerate the host's programs: {why} — a program \
                 the bpf hook never saw is not found"
            );
            if failing.as_deref() != Some(line.as_str()) {
                warn!(detail = %line, "kernel state: BPF cross-view");
                crate::boot::degradation::withdraw(DEGRADATION, &[]);
                if crate::boot::degradation::report(DEGRADATION, &line) {
                    crate::boot::degradation::flush();
                }
                *failing = Some(line);
            }
            Vec::new()
        }
    }
}

/// Lot 304: each baseline program of `found` that `known` proves a known
/// system program (held one of the two ways) gets its loader's pid and uid
/// — signed Low with that proof; an unseen one, a link, or one not proven
/// is left as it was. A program the hook saw loading is no finding at all.
pub fn mark_known_baselines(
    found: &mut [crate::bpf_crossview::Finding],
    known: &dyn Fn(
        u32,
        common::bpf_prog_class::KnownLink,
    ) -> Result<crate::known_system_prog::Known, String>,
) {
    use common::bpf_prog_class::KnownLink;
    for f in found.iter_mut() {
        let crate::bpf_crossview::Finding::Baseline(o) = f else {
            continue;
        };
        if o.is_link {
            continue;
        }
        let mut why = Vec::new();
        for link in [KnownLink::Lsm, KnownLink::RootCgroupSysctl] {
            match known(o.id, link) {
                Ok(k) => {
                    o.known = Some((k.pid, k.uid));
                    break;
                }
                Err(e) => why.push(e),
            }
        }
        if o.known.is_none() {
            tracing::debug!(id = o.id, why = ?why, "kernel state: a baseline program not proven a known system program");
        }
    }
}

/// Start the round: every [`PERIOD`], its findings sent on `tx` (the
/// `fs_protect` source). The first read is the baseline of the taint mask.
/// Lot 290: and `cross`, the BPF cross-view, when the attach set it up.
pub fn spawn(tx: BusSender, mut cross: Option<crate::bpf_crossview::CrossView>) {
    tokio::spawn(async move {
        let mut w = Watch::default();
        let mut failing: Option<String> = None;
        let mut tick = tokio::time::interval(PERIOD);
        let agent_start = crate::known_system_prog::agent_start_ns();
        loop {
            tick.tick().await;
            // lot 304: the cross-view first — the root's programs are told
            // by its enumeration of this round and the loads its hook saw
            let crossed = match cross.as_mut() {
                Some(c) => crossview_round(c, &mut failing, agent_start),
                None => Vec::new(),
            };
            let mut found = {
                let known = |id: u32| match cross.as_ref() {
                    Some(c) => crate::known_system_prog::judge_on_host(
                        id,
                        common::bpf_prog_class::KnownLink::RootCgroupSysctl,
                        c.watch.program(id).as_ref(),
                        agent_start,
                        c.watch.seen().get(&id),
                    ),
                    None => Err("no BPF cross-view on this host".to_string()),
                };
                round(&mut w, Path::new("/"), &known)
            };
            found.extend(crossed);
            for f in found {
                if tx.send(event_of(&f, monotonic_ns())).await.is_err() {
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::kernel_taint::{TAINT_LIVEPATCH, TAINT_OOT_MODULE, TAINT_UNSIGNED_MODULE};

    fn host(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, v) in files {
            let f = d.path().join(p.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, v).unwrap();
        }
        d
    }

    /// Lot 280b (named): the manifest's entry — the mask, its letters, the
    /// livepatches and their state; a mask unread says why.
    #[test]
    fn the_manifest_records_the_taint_and_the_livepatches() {
        let d = host(&[
            ("/proc/sys/kernel/tainted", "12288\n"),
            ("/sys/kernel/livepatch/lp_cve/enabled", "1\n"),
            ("/sys/kernel/livepatch/lp_cve/transition", "0\n"),
            ("/sys/kernel/livepatch/lp_old/enabled", "0\n"),
            ("/sys/kernel/livepatch/lp_new/enabled", "1\n"),
            ("/sys/kernel/livepatch/lp_new/transition", "1\n"),
        ]);
        let k = kernel_code(d.path());
        assert_eq!(k.tainted, Some(TAINT_OOT_MODULE | TAINT_UNSIGNED_MODULE));
        assert_eq!(k.taint, "OE");
        assert_eq!(
            k.livepatches,
            vec![
                "lp_cve".to_string(),
                "lp_new (in transition)".to_string(),
                "lp_old (disabled)".to_string()
            ]
        );
        assert!(k.line().contains("tainted 12288 (OE)"), "{}", k.line());
        let none = kernel_code(host(&[("/proc/sys/kernel/tainted", "0\n")]).path());
        assert_eq!((none.tainted, none.livepatches.len()), (Some(0), 0));
        assert_eq!(none.line(), "not tainted, no livepatch");
        let bad = kernel_code(host(&[("/proc/sys/kernel/tainted", "x\n")]).path());
        assert_eq!(bad.tainted, None);
        assert!(bad.taint.contains("not an integer"), "{}", bad.taint);
        let gone = kernel_code(host(&[]).path());
        assert!(
            gone.taint.contains("/proc/sys/kernel/tainted"),
            "{}",
            gone.taint
        );
    }

    /// Lot 280b (named): a flag of code entering the kernel that appears
    /// while the agent runs is a finding, once; the flags of before the
    /// start are the baseline, a warning's flag is no finding, an unread
    /// mask keeps the baseline.
    #[test]
    fn a_new_code_entry_taint_is_found_once() {
        let mut w = Watch::default();
        assert_eq!(w.taint(Ok(TAINT_OOT_MODULE)), None, "the baseline");
        assert_eq!(w.taint(Ok(TAINT_OOT_MODULE)), None);
        assert_eq!(w.taint(Ok(TAINT_OOT_MODULE | (1 << 9))), None, "a WARN");
        assert_eq!(
            w.taint(Ok(TAINT_OOT_MODULE | (1 << 9) | TAINT_UNSIGNED_MODULE)),
            Some(Finding::Taint {
                new: TAINT_UNSIGNED_MODULE,
                mask: TAINT_OOT_MODULE | (1 << 9) | TAINT_UNSIGNED_MODULE
            })
        );
        assert_eq!(
            w.taint(Ok(TAINT_OOT_MODULE | (1 << 9) | TAINT_UNSIGNED_MODULE)),
            None,
            "once"
        );
        assert_eq!(w.taint(Err("gone".into())), None);
        assert_eq!(
            w.taint(Ok(TAINT_OOT_MODULE
                | (1 << 9)
                | TAINT_UNSIGNED_MODULE
                | TAINT_LIVEPATCH)),
            Some(Finding::Taint {
                new: TAINT_LIVEPATCH,
                mask: TAINT_OOT_MODULE | (1 << 9) | TAINT_UNSIGNED_MODULE | TAINT_LIVEPATCH
            })
        );
        let mut first_unread = Watch::default();
        assert_eq!(first_unread.taint(Err("x".into())), None);
        assert_eq!(
            first_unread.taint(Ok(TAINT_LIVEPATCH)),
            None,
            "the baseline"
        );
    }

    /// Lot 280b (named): a foreign program on the root's slot is found
    /// once per id; a root not as the attach left it is a degradation set
    /// once and cleared when the root is right again; no judge, nothing.
    #[test]
    fn a_foreign_root_program_is_found_once_and_a_wrong_root_degrades() {
        let mut w = Watch::default();
        let n = &not_known;
        assert_eq!(w.root(Ok(None), n), (Vec::new(), None));
        assert_eq!(w.root(Ok(Some(Vec::new())), n), (Vec::new(), None));
        assert_eq!(
            w.root(Ok(Some(vec![812])), n),
            (vec![Finding::RootProgram(812)], None)
        );
        assert_eq!(w.root(Ok(Some(vec![812])), n), (Vec::new(), None), "once");
        assert_eq!(
            w.root(Ok(Some(vec![812, 900])), n),
            (vec![Finding::RootProgram(900)], None)
        );
        let (f, d) = w.root(
            Err("our program (id 7) is not among the root cgroup's".into()),
            n,
        );
        assert!(f.is_empty());
        let line = d.expect("set").expect("a line");
        assert!(line.contains("our program (id 7)"), "{line}");
        assert_eq!(
            w.root(
                Err("our program (id 7) is not among the root cgroup's".into()),
                n
            ),
            (Vec::new(), None),
            "the same line once"
        );
        assert_eq!(w.root(Ok(Some(Vec::new())), n), (Vec::new(), Some(None)));
        assert_eq!(w.root(Ok(Some(Vec::new())), n), (Vec::new(), None));
    }

    fn not_known(_: u32) -> Result<crate::known_system_prog::Known, String> {
        Err("not proven".into())
    }

    fn networkd_monitor(id: u32) -> crate::known_system_prog::Known {
        crate::known_system_prog::Known {
            id,
            entry: 0,
            link_id: 3,
            pid: 631,
            uid: 998,
            comm: "systemd-network".into(),
            seen: false,
        }
    }

    /// Lot 304 (named): a root program `known` proves a known system
    /// program is found once as one, the others beside it as programs not
    /// the agent's; its event is the loader's — pid, uid, name — with the
    /// proof in `target_dev` and the program's id, the operation the same.
    #[test]
    fn a_known_root_program_is_found_once_with_its_loader() {
        let mut w = Watch::default();
        let known = |id: u32| {
            if id == 35 {
                Ok(networkd_monitor(35))
            } else {
                Err("not proven".to_string())
            }
        };
        assert_eq!(
            w.root(Ok(Some(vec![35, 812])), &known),
            (
                vec![
                    Finding::KnownRootProgram(networkd_monitor(35)),
                    Finding::RootProgram(812)
                ],
                None
            )
        );
        assert_eq!(
            w.root(Ok(Some(vec![35, 812])), &known),
            (Vec::new(), None),
            "once"
        );
        let e = event_of(&Finding::KnownRootProgram(networkd_monitor(35)), 7);
        assert!(
            matches!(
                &e,
                Event::FsProtectDenial {
                    pid: 631,
                    uid: 998,
                    comm,
                    target_dev,
                    target_ino: 35,
                    operation: FsProtectOperation::SysctlRootProg,
                    timestamp_ns: 7,
                } if comm == "systemd-network"
                    && *target_dev == common::bpf_prog_class::root_prog_known_dev(0, false, 3)
            ),
            "{e:?}"
        );
        let seen = crate::known_system_prog::Known {
            seen: true,
            ..networkd_monitor(90)
        };
        assert!(matches!(
            event_of(&Finding::KnownRootProgram(seen), 7),
            Event::FsProtectDenial { target_dev, target_ino: 90, .. }
                if common::bpf_prog_class::root_prog_known_of(target_dev) == Some((0, true, 3))
        ));
        // a program not proven: the kernel's act, no proof
        assert!(matches!(
            event_of(&Finding::RootProgram(812), 7),
            Event::FsProtectDenial { pid: 0, uid: 0, target_dev: 0, ref comm, .. } if comm == "kernel"
        ));
    }

    /// Lot 280b: the events — the kernel's act, the taint's new flags and
    /// mask, the program's id.
    #[test]
    fn the_findings_are_signed_as_the_kernels_acts() {
        let e = event_of(
            &Finding::Taint {
                new: TAINT_UNSIGNED_MODULE,
                mask: TAINT_UNSIGNED_MODULE | 1,
            },
            9,
        );
        let Event::FsProtectDenial {
            pid,
            uid,
            comm,
            target_dev,
            target_ino,
            operation,
            timestamp_ns,
        } = e
        else {
            panic!("{e:?}")
        };
        assert_eq!((pid, uid, comm.as_str()), (0, 0, "kernel"));
        assert_eq!(
            (target_dev, target_ino, timestamp_ns),
            (TAINT_UNSIGNED_MODULE, TAINT_UNSIGNED_MODULE | 1, 9)
        );
        assert_eq!(operation, FsProtectOperation::KernelTaint);
        // lot 290: a cross-view finding carries the object
        let o = crate::bpf_crossview::Object {
            is_link: false,
            id: 77,
            object_type: 29,
            name: "hide".into(),
            tag: 0xabcd,
            attach: "bpf_lsm_file_open".into(),
            early: false,
            known: None,
        };
        let e = event_of(
            &Finding::Bpf(crate::bpf_crossview::Finding::Unseen(o.clone())),
            3,
        );
        assert!(
            matches!(
                &e,
                Event::FsProtectDenial {
                    pid: 0,
                    target_dev: 0xabcd,
                    operation: FsProtectOperation::BpfUnseen,
                    comm,
                    target_ino,
                    ..
                } if comm == "hide@bpf_lsm_file_open"
                    && *target_ino == common::bpf_prog_class::crossview_ino(false, false, 29, 77)
            ),
            "{e:?}"
        );
        // the kernel's own program: its early bit carried
        let kernel_s = crate::bpf_crossview::Object { early: true, ..o };
        assert!(matches!(
            event_of(&Finding::Bpf(crate::bpf_crossview::Finding::Baseline(kernel_s)), 3),
            Event::FsProtectDenial {
                operation: FsProtectOperation::BpfBaseline,
                target_ino,
                ..
            } if target_ino == common::bpf_prog_class::crossview_ino(false, true, 29, 77)
        ));
        assert!(matches!(
            event_of(&Finding::RootProgram(812), 1),
            Event::FsProtectDenial {
                target_ino: 812,
                operation: FsProtectOperation::SysctlRootProg,
                ..
            }
        ));
    }

    /// Lot 304 (named): a baseline program proven a known system program
    /// (PID 1's `restrict_filesystems`) carries its loader — the record's
    /// pid and uid, the known bit beside its type and id; an unseen program
    /// of the same name, a link, and a baseline program not proven are left
    /// as they were.
    #[test]
    fn a_known_baseline_program_carries_its_loader() {
        use crate::bpf_crossview::{Finding as B, Object};
        use common::bpf_prog_class::{crossview_ino, KnownLink, CROSSVIEW_KNOWN_BIT};
        let o = |id: u32, is_link: bool| Object {
            is_link,
            id,
            object_type: 29,
            name: "restrict_filesy".into(),
            tag: 0xe893,
            attach: "bpf_lsm_file_open".into(),
            early: false,
            known: None,
        };
        let mut found = vec![
            B::Baseline(o(21, false)),
            B::Unseen(o(22, false)),
            B::Baseline(o(23, true)),
            B::Baseline(o(24, false)),
        ];
        let asked = std::cell::RefCell::new(Vec::new());
        mark_known_baselines(&mut found, &|id, link| {
            asked.borrow_mut().push((id, link));
            if id == 21 && link == KnownLink::Lsm || id == 24 && link == KnownLink::RootCgroupSysctl
            {
                Ok(crate::known_system_prog::Known {
                    id,
                    entry: 1,
                    link_id: 2,
                    pid: if id == 21 { 1 } else { 631 },
                    uid: if id == 21 { 0 } else { 998 },
                    comm: "systemd".into(),
                    seen: false,
                })
            } else {
                Err("not proven".into())
            }
        });
        assert_eq!(
            found,
            vec![
                B::Baseline(Object {
                    known: Some((1, 0)),
                    ..o(21, false)
                }),
                B::Unseen(o(22, false)),
                B::Baseline(o(23, true)),
                B::Baseline(Object {
                    known: Some((631, 998)),
                    ..o(24, false)
                }),
            ]
        );
        // only the baseline programs were asked, each kind until one proves it
        assert_eq!(
            *asked.borrow(),
            vec![
                (21, KnownLink::Lsm),
                (24, KnownLink::Lsm),
                (24, KnownLink::RootCgroupSysctl)
            ]
        );
        let e = event_of(&Finding::Bpf(found[0].clone()), 3);
        assert!(
            matches!(
                &e,
                Event::FsProtectDenial {
                    pid: 1,
                    uid: 0,
                    operation: FsProtectOperation::BpfBaseline,
                    target_ino,
                    ..
                } if *target_ino == crossview_ino(false, false, 29, 21) | CROSSVIEW_KNOWN_BIT
            ),
            "{e:?}"
        );
        // not proven: the kernel's act, no bit
        let e = event_of(&Finding::Bpf(found[3].clone()), 3);
        assert!(
            matches!(&e, Event::FsProtectDenial { pid: 631, .. }),
            "{e:?}"
        );
        let e = event_of(&Finding::Bpf(B::Baseline(o(24, false))), 3);
        assert!(
            matches!(
                &e,
                Event::FsProtectDenial { pid: 0, uid: 0, target_ino, .. }
                    if *target_ino & CROSSVIEW_KNOWN_BIT == 0
            ),
            "{e:?}"
        );
    }
}
