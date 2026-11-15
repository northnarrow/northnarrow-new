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
//! * Lot 349 (pre-alpha R001): the agent's own CPUs ([`crate::own_cpus`]):
//!   its threads' affinity and its cgroup's effective CPUs against those it
//!   should run on — a confinement (a sibling cgroup partition, its own
//!   cgroup's `cpuset.cpus`, a thread's affinity, a move) is a signed High
//!   detection (`FsProtectOperation::CpuConfined`) and a degradation while
//!   it holds.
//!
//! The detections go through the bus as the `fs_protect` source's events
//! (the kernel's refusals' source): judged, signed and counted like them.
//!
//! The review of #565 (F2): each is a sole trace (`common::wire::
//! is_sole_trace`: no budget, no cap), and root makes BPF objects at will —
//! a round names at most [`ROUND_QUOTA`] findings of each kind, the most
//! dangerous first, and signs the rest in ONE summary record with their
//! counts ([`within_quota`]); each held back is listed in the cross-view's
//! status file and counted in `nn-admin status` ([`held_back_counts`]).
//! Its re-check: a held program's records are never under the quota (R1);
//! a BPF object is ranked by what it can do, the summary names each kind's
//! highest-ranked, first and last held back, and what a round held back is
//! carried into the next until named ([`Quota`], R2).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// The review of #565 (F2): the findings of one kind a round signs by name
/// ([`within_quota`]); the rest are counted in the round's one summary
/// record. At most half the bus's P0 reserve: a round's named records of
/// one kind never fill the room the rare tamper events keep (a module
/// load, an exploit post-condition, a security tool signalled).
pub const ROUND_QUOTA: usize = 32;
const _: () = assert!(ROUND_QUOTA * 2 <= nn_core::bus::P0_RESERVE);

/// The taint mask under `root` (`/` on the host, a directory in the
/// tests). The re-check of #558 (F7): read within the round's deadline
/// ([`crate::state_read::ROUND_READER`]) — a FUSE file bound over it no
/// longer stalls the round.
pub fn tainted(root: &Path) -> Result<u64, String> {
    let path = root.join(TAINTED.trim_start_matches('/'));
    let text = crate::state_read::ROUND_READER
        .read_state(&path)
        .map_err(|e| format!("{TAINTED}: {e}"))?;
    text.trim()
        .parse::<u64>()
        .map_err(|_| format!("{TAINTED} reads {:?}, not an integer", text.trim()))
}

/// Each livepatch under `root` and its state, sorted: `name`, `name
/// (disabled)`, `name (in transition)`.
pub fn livepatches(root: &Path) -> Vec<String> {
    let dir = root.join(LIVEPATCH_DIR.trim_start_matches('/'));
    // lot 353: beneath the `/sys` root the agent's start anchored
    let Ok(entries) = antitamper_bpf::kernel_roots::read_dir(&dir) else {
        return Vec::new();
    };
    let flag = |p: &Path, f: &str| {
        antitamper_bpf::kernel_roots::read_to_string(p.join(f))
            .ok()
            .map(|t| t.trim() == "1")
    };
    let mut out: Vec<String> = entries
        .into_iter()
        .filter(|n| antitamper_bpf::kernel_roots::is_dir(dir.join(n)))
        .map(|n| {
            let name = n.to_string_lossy().to_string();
            let p = dir.join(&n);
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
    /// Lot 349: the agent runs on fewer CPUs than it should.
    Cpus(crate::own_cpus::Confinement),
    /// The review of #565 (F2): what the round's quota held back, counted
    /// — one per round that held some back; its re-check (R2): naming each
    /// kind's highest-ranked, first and last held back.
    HeldBack(HeldBack),
}

/// The review of #565 (F2; its re-check, R2): a round's summary of what its
/// quota held back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBack {
    /// The counts per kind (the record's `target_dev` and `target_ino`).
    pub counts: common::wire::SoleTraceSummary,
    /// The record's `comm`: for each kind that held some back, its name,
    /// its count and three of them ([`named_as`]) — the highest-ranked
    /// held back (`top`), the first and the last in the round's order — the
    /// kinds apart by `; `: `bpf_unseen 968 top=prog:1040:cgroup_sock
    /// first=prog:33:socket_filter last=prog:1000:socket_filter`.
    pub objects: String,
}

/// The review of #565 (F2): the kinds a round's quota counts apart — the
/// fields of `common::wire::SoleTraceSummary`. Its re-check (R1): a held
/// program's records — its outliving, the program found unseen or in the
/// baseline — are of no kind, never under the quota: the held set bounds
/// them (1,024 ids, each signed once), and they are the only record of a
/// held load whose own record the ring had no room for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Unseen,
    Baseline,
    RootProgram,
    Taint,
    Cpus,
}

impl Kind {
    /// Every kind, in the summary's order.
    pub const ALL: [Kind; 5] = [
        Kind::Unseen,
        Kind::Baseline,
        Kind::RootProgram,
        Kind::Taint,
        Kind::Cpus,
    ];

    /// The name `nn-admin status` counts it by (its record's operation).
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Unseen => "bpf_unseen",
            Kind::Baseline => "bpf_baseline",
            Kind::RootProgram => "sysctl_root_prog",
            Kind::Taint => "kernel_taint",
            Kind::Cpus => "cpu_confined",
        }
    }

    /// The kind of finding `f` — `None` (never under the quota) for the
    /// summary itself and for every record about a held program.
    pub fn of(f: &Finding) -> Option<Kind> {
        use crate::bpf_crossview::Finding as B;
        Some(match f {
            Finding::Bpf(B::HeldOutlived(..)) => return None,
            Finding::Bpf(B::Unseen(o) | B::Baseline(o)) if o.held.is_some() => return None,
            Finding::Taint { .. } => Kind::Taint,
            Finding::RootProgram(_) | Finding::KnownRootProgram(_) => Kind::RootProgram,
            Finding::Bpf(B::Unseen(_)) => Kind::Unseen,
            Finding::Bpf(B::Baseline(_)) => Kind::Baseline,
            Finding::Cpus(_) => Kind::Cpus,
            Finding::HeldBack(_) => return None,
        })
    }
}

/// The re-check of #565 (R2): the rank of a proven known system program —
/// after every reach.
const RANK_KNOWN: u8 = common::bpf_prog_class::REACH_FILTER + 1;

/// The review of #565 (F2; its re-check, R2): the order a kind's findings
/// are named in under the quota, lowest first — a BPF object by what it can
/// do (`common::bpf_prog_class::reach`): a held program (a signal or write
/// helper or kfunc), an fmod_ret and a link whose program is hidden first,
/// then the types run in the kernel's paths or on the host's traffic
/// (kprobe, fentry, LSM, tracing, struct_ops, syscall, XDP, tc, …), then
/// the others, then socket filters and cgroup_skb; a proven known system
/// program last. Within a rank, the round's order (the carried first).
pub fn rank(f: &Finding) -> u8 {
    use crate::bpf_crossview::Finding as B;
    use common::bpf_prog_class::{reach, REACH_KERNEL, REACH_SIGNAL_OR_WRITE};
    match f {
        Finding::Bpf(B::Unseen(o) | B::Baseline(o) | B::HeldOutlived(o, _)) => {
            if o.known.is_some() {
                RANK_KNOWN
            } else if o.is_link {
                REACH_SIGNAL_OR_WRITE
            } else {
                reach(o.object_type, o.attach_type, o.held.is_some(), o.early)
            }
        }
        Finding::KnownRootProgram(_) => RANK_KNOWN,
        _ => REACH_KERNEL,
    }
}

/// The re-check of #565 (R2): how the summary names a finding held back —
/// `prog:<id>:<type>` or `link:<id>:<link type>`, a root `cgroup/sysctl`
/// program `prog:<id>:cgroup_sysctl`, a taint `taint:<new flags>`, a
/// confinement `cpus:<cause>` (no spaces: the comm's fields are apart by
/// them).
pub fn named_as(f: &Finding) -> String {
    use crate::bpf_crossview::Finding as B;
    use common::bpf_prog_class::{link_type_name, prog_type_name};
    let s = match f {
        Finding::Bpf(B::Unseen(o) | B::Baseline(o) | B::HeldOutlived(o, _)) => {
            if o.is_link {
                format!("link:{}:{}", o.id, link_type_name(o.object_type))
            } else {
                format!("prog:{}:{}", o.id, prog_type_name(o.object_type))
            }
        }
        Finding::RootProgram(id) => format!("prog:{id}:cgroup_sysctl"),
        Finding::KnownRootProgram(k) => format!("prog:{}:cgroup_sysctl", k.id),
        Finding::Taint { new, .. } => format!("taint:{new:#x}"),
        Finding::Cpus(c) => format!("cpus:{}", c.cause.subject()),
        Finding::HeldBack(_) => String::new(),
    };
    s.replace([' ', ';'], "_")
}

/// The re-check of #565 (R2): the findings a round's quota held back that
/// the next round carries ([`Quota`]) — at most this many, the
/// highest-ranked kept (the others are counted, and listed `suppressed`
/// while the enumeration shows them).
pub const CARRY_MAX: usize = 1_024;

/// One round within its quota ([`within_quota`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Within {
    /// The findings to sign: those named, in the round's order, then the
    /// summary when some were held back.
    pub signed: Vec<Finding>,
    /// Those held back, in the round's order: the carried ones first.
    pub held: Vec<Finding>,
    /// How many of `held` (its first ones) an earlier round carried —
    /// counted in `nn-admin status` when first held back.
    pub again: usize,
}

/// The review of #565 (F2; its re-check, R2): a round's findings within the
/// quota — `carried` (what earlier rounds held back, [`Quota`]) first, then
/// `found`: at most `quota` of each kind ([`Kind`]) named, the most
/// dangerous first ([`rank`], then the round's order), and, when the quota
/// held some back, ONE more finding last: their counts per kind and the
/// objects it names ([`Finding::HeldBack`], each count saturating at its
/// field). One kind's flood never holds back another kind's finding, nor a
/// held program's (of no kind).
pub fn within_quota(carried: Vec<Finding>, found: Vec<Finding>, quota: usize) -> Within {
    let from_carry = carried.len();
    let mut all = carried;
    all.extend(found);
    let mut by_rank: Vec<usize> = (0..all.len()).collect();
    by_rank.sort_by_key(|i| rank(&all[*i]));
    let mut keep = vec![true; all.len()];
    let mut named = [0usize; Kind::ALL.len()];
    // each kind's held back, highest-ranked first
    let mut held_of: [Vec<usize>; Kind::ALL.len()] = std::array::from_fn(|_| Vec::new());
    for i in by_rank {
        let Some(kind) = Kind::of(&all[i]) else {
            continue;
        };
        if named[kind as usize] < quota {
            named[kind as usize] += 1;
        } else {
            keep[i] = false;
            held_of[kind as usize].push(i);
        }
    }
    let mut objects = Vec::new();
    for kind in Kind::ALL {
        let h = &held_of[kind as usize];
        let (Some(top), Some(first), Some(last)) = (h.first(), h.iter().min(), h.iter().max())
        else {
            continue;
        };
        objects.push(format!(
            "{} {} top={} first={} last={}",
            kind.name(),
            h.len(),
            named_as(&all[*top]),
            named_as(&all[*first]),
            named_as(&all[*last]),
        ));
    }
    let again = (0..from_carry).filter(|i| !keep[*i]).count();
    let mut out = Within {
        again,
        ..Within::default()
    };
    for (f, k) in all.into_iter().zip(keep) {
        if k {
            out.signed.push(f);
        } else {
            out.held.push(f);
        }
    }
    if !out.held.is_empty() {
        let c = |k: Kind| held_of[k as usize].len();
        out.signed.push(Finding::HeldBack(HeldBack {
            counts: common::wire::SoleTraceSummary {
                unseen: u32::try_from(c(Kind::Unseen)).unwrap_or(u32::MAX),
                baseline: u32::try_from(c(Kind::Baseline)).unwrap_or(u32::MAX),
                carried: u16::try_from(again).unwrap_or(u16::MAX),
                root_prog: u16::try_from(c(Kind::RootProgram)).unwrap_or(u16::MAX),
                taint: u8::try_from(c(Kind::Taint)).unwrap_or(u8::MAX),
                cpus: u8::try_from(c(Kind::Cpus)).unwrap_or(u8::MAX),
                quota: u16::try_from(quota).unwrap_or(u16::MAX),
            },
            objects: objects.join("; "),
        }));
    }
    out
}

/// The re-check of #565 (R2): the round's quota across rounds — what one
/// round held back is carried into the next, first in its rank, until a
/// round names it (once: a carried finding is never found again, the
/// cross-view and the root's watch sign each object once).
#[derive(Debug, Default)]
pub struct Quota {
    /// The findings held back the next round carries (at most
    /// [`CARRY_MAX`], in the round's order).
    carry: Vec<Finding>,
}

impl Quota {
    /// One round's `found` within `quota` ([`within_quota`]), with what
    /// the last round carried; what it holds back is carried in turn — the
    /// [`CARRY_MAX`] highest-ranked.
    pub fn apply(&mut self, found: Vec<Finding>, quota: usize) -> Within {
        let w = within_quota(std::mem::take(&mut self.carry), found, quota);
        let mut by_rank: Vec<usize> = (0..w.held.len()).collect();
        by_rank.sort_by_key(|i| rank(&w.held[*i]));
        by_rank.truncate(CARRY_MAX);
        by_rank.sort_unstable();
        self.carry = by_rank.into_iter().map(|i| w.held[i].clone()).collect();
        w
    }

    /// The findings the next round carries.
    pub fn carried(&self) -> &[Finding] {
        &self.carry
    }
}

/// The review of #565 (F2): the findings the rounds' quota held back since
/// the start, per [`Kind`] (`nn-admin status`).
static HELD_BACK: [AtomicU64; Kind::ALL.len()] = [const { AtomicU64::new(0) }; Kind::ALL.len()];

/// Count `held` (a round's findings the quota held back for the first
/// time: the re-check of #565, R2 — a carried one is counted once) in
/// [`held_back_counts`].
fn count_held_back(held: &[Finding]) {
    for f in held {
        if let Some(k) = Kind::of(f) {
            HELD_BACK[k as usize].fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The review of #565 (F2): the findings the rounds' quota held back since
/// the start, per kind that held some back (`nn-admin status --key`) —
/// each also counted in a signed summary record, and listed in the
/// cross-view's status file when it is a BPF object.
pub fn held_back_counts() -> Vec<(String, u64)> {
    Kind::ALL
        .iter()
        .map(|k| {
            (
                k.name().to_string(),
                HELD_BACK[*k as usize].load(Ordering::Relaxed),
            )
        })
        .filter(|(_, n)| *n > 0)
        .collect()
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
        // lot 349: what the cause names (a partition, a cgroup, a thread)
        Finding::Cpus(c) => {
            comm = c.cause.subject();
            (
                FsProtectOperation::CpuConfined,
                c.target_dev(),
                c.target_ino(),
            )
        }
        // lot 349 (the re-check of #558, item 2): a held program after
        // its window — the program's id and the verdict of its load
        Finding::Bpf(crate::bpf_crossview::Finding::HeldOutlived(o, verdict)) => {
            comm = common::bpf_prog_class::object_comm(&o.name, &o.attach);
            (
                FsProtectOperation::BpfHeldLoad,
                common::wire::bpf_held_dev(common::wire::BPF_HELD_OUTLIVED, *verdict),
                u64::from(o.id),
            )
        }
        // the review of #565 (F2): the counts the round's quota held back;
        // its re-check (R2): each kind's highest-ranked, first and last
        Finding::HeldBack(h) => {
            comm = h.objects.clone();
            (
                FsProtectOperation::SoleTraceSummary,
                h.counts.target_dev(),
                h.counts.target_ino(),
            )
        }
        Finding::Bpf(b) => {
            use crate::bpf_crossview::Finding as B;
            let (op, o) = match b {
                B::Baseline(o) => (FsProtectOperation::BpfBaseline, o),
                B::Unseen(o) | B::HeldOutlived(o, _) => (FsProtectOperation::BpfUnseen, o),
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

/// Lot 290: one cross-view round — its findings (logged once the round's
/// quota is applied: the review of #565, F2); an error is a signed
/// degradation while it holds ([`crate::bpf_crossview::DEGRADATION`]).
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
                known_within(id, link, cross.watch.program(id), agent_start, None)
            });
            if failing.take().is_some() {
                info!("kernel state: the BPF cross-view runs again");
                crate::boot::degradation::withdraw(DEGRADATION, &[]);
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

/// The re-check of #558 (F7): [`crate::known_system_prog::judge_on_host`]
/// within the round's deadline — its reads of the loader's `/proc` files
/// (`stat`, `status`, `comm`, `fdinfo`) are paths a FUSE file can be bound
/// over; past the deadline the program is not proven (the stricter record).
fn known_within(
    id: u32,
    link: common::bpf_prog_class::KnownLink,
    prog: Option<crate::known_system_prog::Program>,
    agent_start: Option<u64>,
    seen: Option<common::bpf_prog_class::SeenLoad>,
) -> Result<crate::known_system_prog::Known, String> {
    crate::state_read::ROUND_READER
        .run("a loader's /proc files", move || {
            crate::known_system_prog::judge_on_host(
                id,
                link,
                prog.as_ref(),
                agent_start,
                seen.as_ref(),
            )
        })
        .and_then(|r| r)
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

/// The journal's lines of a round within its quota: each cross-view
/// finding signed (the others are logged where they are found), one line
/// for what the quota held back, each held back at debug.
fn log_round(found: &[Finding], held: &[Finding]) {
    for f in found {
        match f {
            Finding::Bpf(b) => {
                warn!(finding = ?b, "kernel state: a BPF object the bpf hook never saw loading")
            }
            Finding::HeldBack(h) => warn!(
                quota = h.counts.quota,
                held_back = h.counts.total(),
                carried = h.counts.carried,
                unseen = h.counts.unseen,
                baseline = h.counts.baseline,
                root_prog = h.counts.root_prog,
                taint = h.counts.taint,
                cpus = h.counts.cpus,
                named = %h.objects,
                "kernel state: findings past the round's quota per kind held back — counted in \
                 one signed record, listed in the BPF cross-view's status file, carried into the \
                 next round"
            ),
            _ => {}
        }
    }
    for f in held {
        tracing::debug!(finding = ?f, "kernel state: a finding past the round's quota (counted)");
    }
}

/// The BPF objects of `found` (their keys).
fn objects(found: &[Finding]) -> impl Iterator<Item = (bool, u32)> + '_ {
    found.iter().filter_map(|f| match f {
        Finding::Bpf(b) => Some(b.object()),
        _ => None,
    })
}

/// Start the round: every [`PERIOD`], its findings sent on `tx` (the
/// `fs_protect` source). The first read is the baseline of the taint mask.
/// Lot 290: and `cross`, the BPF cross-view, when the attach set it up.
pub fn spawn(tx: BusSender, mut cross: Option<crate::bpf_crossview::CrossView>) {
    tokio::spawn(async move {
        let mut w = Watch::default();
        let mut cpus = crate::own_cpus::Watch::default();
        let mut failing: Option<String> = None;
        let mut tick = tokio::time::interval(PERIOD);
        let agent_start = crate::known_system_prog::agent_start_ns();
        let mut quota = Quota::default();
        loop {
            tick.tick().await;
            // Lot 353 (pre-alpha Phase 3, X6): the round's reads are the
            // kernel's files, read beneath the roots the start anchored
            // (`antitamper_bpf::kernel_roots`) — and the round runs off the
            // runtime's worker all the same: a read that blocks never holds
            // the admin socket's tasks (its STATUS) or the others.
            let w = crate::runtime::off_the_runtime(|| {
                // lot 304: the cross-view first — the root's programs are
                // told by its enumeration of this round and the loads its
                // hook saw
                let crossed = match cross.as_mut() {
                    Some(c) => crossview_round(c, &mut failing, agent_start),
                    None => Vec::new(),
                };
                let mut found = {
                    let known = |id: u32| match cross.as_ref() {
                        Some(c) => known_within(
                            id,
                            common::bpf_prog_class::KnownLink::RootCgroupSysctl,
                            c.watch.program(id),
                            agent_start,
                            c.watch.seen().get(&id).copied(),
                        ),
                        None => Err("no BPF cross-view on this host".to_string()),
                    };
                    round(&mut w, Path::new("/"), &known)
                };
                found.extend(crossed);
                // lot 349: the agent's own CPUs — the re-check of #558
                // (F7): a read of this round that did not answer makes it
                // unjudged
                found.extend(
                    crate::own_cpus::round(&mut cpus, &crate::state_read::ROUND_READER)
                        .map(Finding::Cpus),
                );
                // the review of #565 (F2): at most ROUND_QUOTA of each kind
                // by name, the rest counted in one summary record — in the
                // status file and `nn-admin status` too; its re-check (R2):
                // the rest carried into the next round until named. The
                // status file's write (by path, `/run/northnarrow`) stays
                // off the runtime with the round (lot 353).
                let w = quota.apply(found, ROUND_QUOTA);
                log_round(&w.signed, &w.held);
                count_held_back(&w.held[w.again..]);
                if let Some(c) = cross.as_mut() {
                    c.quota_round(objects(&w.signed), objects(&w.held));
                    c.write_status();
                }
                w
            });
            for f in w.signed {
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
            attach_type: 0,
            held: None,
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
        // the re-check of #558 (item 2): a held program after its window,
        // signed as its held load's record with the use "outlived"
        let e = event_of(
            &Finding::Bpf(crate::bpf_crossview::Finding::HeldOutlived(
                o.clone(),
                (9u64 << 32) | 2,
            )),
            3,
        );
        assert!(
            matches!(
                &e,
                Event::FsProtectDenial {
                    pid: 0,
                    target_ino: 77,
                    operation: FsProtectOperation::BpfHeldLoad,
                    comm,
                    target_dev,
                    ..
                } if comm == "hide@bpf_lsm_file_open"
                    && common::wire::bpf_held_of(*target_dev)
                        == (common::wire::BPF_HELD_OUTLIVED, 9, 2)
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
            attach_type: 0,
            held: None,
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

    /// Lot 349 (pre-alpha R001): a confinement of the agent's CPUs is signed
    /// as the kernel's act (pid 0), `comm` what its cause names, the cause
    /// and counts in `target_dev`, the CPUs left in `target_ino`.
    #[test]
    fn a_cpu_confinement_is_signed_as_cpu_confined() {
        use crate::own_cpus::{Cause, Confinement, CAUSE_PARTITION};
        let c = Confinement {
            left: vec![0],
            expected: vec![0, 1, 2, 3],
            cause: Cause::Partition(vec!["/k349part root 1-3".into()]),
        };
        let Event::FsProtectDenial {
            pid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } = event_of(&Finding::Cpus(c), 4)
        else {
            panic!("not a denial")
        };
        assert_eq!(operation, FsProtectOperation::CpuConfined);
        assert_eq!((pid, comm.as_str(), target_ino), (0, "/k349part", 1));
        assert_eq!(
            common::wire::cpu_confined_of(target_dev),
            (CAUSE_PARTITION, 1, 4, 0)
        );
    }

    /// The review of #565 (F2) helpers: a program of type `t`, id `id`.
    fn object(id: u32, t: u32) -> crate::bpf_crossview::Object {
        crate::bpf_crossview::Object {
            is_link: false,
            id,
            object_type: t,
            name: format!("p{id}"),
            tag: u64::from(id),
            attach: "-".into(),
            early: false,
            known: None,
            attach_type: 0,
            held: None,
        }
    }

    fn unseen(id: u32, t: u32) -> Finding {
        Finding::Bpf(crate::bpf_crossview::Finding::Unseen(object(id, t)))
    }

    /// One round with nothing carried (the tests of a single round).
    fn one_round(found: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
        let w = within_quota(Vec::new(), found, ROUND_QUOTA);
        assert_eq!(w.again, 0);
        (w.signed, w.held)
    }

    fn summary_of(found: &[Finding]) -> Vec<common::wire::SoleTraceSummary> {
        found
            .iter()
            .filter_map(|f| match event_of(f, 1) {
                Event::FsProtectDenial {
                    operation: FsProtectOperation::SoleTraceSummary,
                    target_dev,
                    target_ino,
                    pid: 0,
                    ..
                } => Some(common::wire::SoleTraceSummary::of(target_dev, target_ino)),
                _ => None,
            })
            .collect()
    }

    /// The summary's `comm` (the objects it names).
    fn named_of(found: &[Finding]) -> String {
        found
            .iter()
            .find_map(|f| match event_of(f, 1) {
                Event::FsProtectDenial {
                    operation: FsProtectOperation::SoleTraceSummary,
                    comm,
                    ..
                } => Some(comm),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn ids(found: &[Finding]) -> Vec<(bool, u32)> {
        objects(found).collect()
    }

    /// The review of #565 (F2): root loaded thousands of socket filters
    /// faster than the hook's seen map keeps them, and each came back a
    /// round later as a High `bpf_unseen` record — never capped, taking the
    /// rare events' P0 reserve and uid 0's budget. A round now names
    /// ROUND_QUOTA of a kind and signs the rest in exactly ONE summary
    /// record with their count (a sole trace: never dropped, never
    /// capped); nothing is dropped silently.
    #[test]
    fn a_flood_beyond_the_round_s_quota_is_quota_records_and_one_signed_summary() {
        let flood: Vec<Finding> = (100..1_100).map(|id| unseen(id, 1)).collect();
        let (signed, held) = one_round(flood);
        assert_eq!(signed.len(), ROUND_QUOTA + 1, "quota + 1 summary");
        assert_eq!(held.len(), 1_000 - ROUND_QUOTA);
        let summaries = summary_of(&signed);
        assert_eq!(summaries.len(), 1, "exactly one summary");
        assert!(
            matches!(signed.last(), Some(Finding::HeldBack(_))),
            "the summary last"
        );
        let s = summaries[0];
        assert_eq!(s.unseen as usize, 1_000 - ROUND_QUOTA);
        assert_eq!(
            s.total() as usize,
            held.len(),
            "every one held back counted"
        );
        assert_eq!(s.quota as usize, ROUND_QUOTA);
        assert_eq!(
            s.baseline + u32::from(s.carried) + u32::from(s.root_prog),
            0
        );
        // the named ones are signed as before, in the round's order
        let named: Vec<u32> = ids(&signed).into_iter().map(|k| k.1).collect();
        assert_eq!(named, (100..100 + ROUND_QUOTA as u32).collect::<Vec<_>>());
        // at the quota, or under it: no summary
        let (signed, held) = one_round((0..ROUND_QUOTA as u32).map(|i| unseen(i, 1)).collect());
        assert_eq!((signed.len(), held.len()), (ROUND_QUOTA, 0));
        assert!(summary_of(&signed).is_empty());
        assert_eq!(
            within_quota(Vec::new(), Vec::new(), ROUND_QUOTA),
            Within::default()
        );
        // the quota is at most half the bus's P0 reserve
        const { assert!(ROUND_QUOTA * 2 <= nn_core::bus::P0_RESERVE) };
        // and the summary is a sole trace: no budget, cap or coalescing
        let Some(h @ Finding::HeldBack(_)) = signed_summary(1_000) else {
            panic!("no summary")
        };
        let e = event_of(&h, 1);
        assert!(nn_core::bus::sole_trace(&e), "{e:?}");
    }

    fn signed_summary(n: u32) -> Option<Finding> {
        one_round((0..n).map(|id| unseen(id, 1)).collect()).0.pop()
    }

    /// The review of #565 (F2): a flood of one kind holds back nothing of
    /// another — the round's other findings (a taint flag, the agent's
    /// CPUs, a root cgroup/sysctl program, a held program outliving its
    /// window, the start's baseline under its own quota) are each still
    /// signed by name the round the flood comes; the summary counts each
    /// kind apart.
    #[test]
    fn one_kind_s_flood_never_holds_back_another_kind_s_findings() {
        use crate::bpf_crossview::Finding as B;
        let mut found: Vec<Finding> = (1_000..1_100).map(|id| unseen(id, 1)).collect();
        found.extend((2_000..2_040).map(|id| Finding::Bpf(B::Baseline(object(id, 8)))));
        found.push(Finding::Taint {
            new: 1 << 12,
            mask: 1 << 12,
        });
        found.push(Finding::RootProgram(812));
        found.push(Finding::Bpf(B::HeldOutlived(object(77, 2), 0x0b_0000_0002)));
        found.push(Finding::Cpus(crate::own_cpus::Confinement {
            left: vec![0],
            expected: vec![0, 1],
            cause: crate::own_cpus::Cause::Partition(vec!["/x root 1".into()]),
        }));
        let (signed, held) = one_round(found);
        let n = |k: Kind| signed.iter().filter(|f| Kind::of(f) == Some(k)).count();
        assert_eq!(n(Kind::Unseen), ROUND_QUOTA);
        assert_eq!(n(Kind::Baseline), ROUND_QUOTA);
        for k in [Kind::Taint, Kind::RootProgram, Kind::Cpus] {
            assert_eq!(n(k), 1, "{k:?} held back by another kind's flood");
        }
        assert!(
            ids(&signed).contains(&(false, 77)),
            "the outliving held back by another kind's flood"
        );
        assert_eq!(held.len(), (100 - ROUND_QUOTA) + (40 - ROUND_QUOTA));
        let s = summary_of(&signed);
        assert_eq!(s.len(), 1);
        assert_eq!(
            (
                s[0].unseen,
                s[0].baseline,
                s[0].carried,
                s[0].root_prog,
                s[0].taint,
                s[0].cpus
            ),
            (
                (100 - ROUND_QUOTA) as u32,
                (40 - ROUND_QUOTA) as u32,
                0,
                0,
                0,
                0
            )
        );
        // every finding is signed or held back, none lost
        assert_eq!(signed.len() - 1 + held.len(), 100 + 40 + 4);
    }

    /// The re-check of #565 (R1): a held load the ring had no room for is
    /// refused and counted, and its program — taken by id in the window —
    /// is named only by its outliving; 40 outlivings in one round held 33
    /// to 40 back under the quota, so a root holding 32 other held programs
    /// alive left that one counted only. A held program's records — its
    /// outliving, the program found unseen or in the baseline — are of no
    /// kind: every one is named, whatever else the round found.
    #[test]
    fn a_held_program_s_records_are_never_under_the_round_s_quota() {
        use crate::bpf_crossview::Finding as B;
        let held = |id: u32| crate::bpf_crossview::Object {
            held: Some(0x0b_0000_0002),
            ..object(id, 2)
        };
        // the probe of the re-check: 40 outlivings of kprobes
        let found: Vec<Finding> = (1..=40)
            .map(|id| Finding::Bpf(B::HeldOutlived(object(id, 2), 0x0b_0000_0002)))
            .collect();
        let (signed, held_back) = one_round(found);
        assert!(held_back.is_empty(), "{held_back:?}");
        assert_eq!(
            ids(&signed),
            (1..=40).map(|id| (false, id)).collect::<Vec<_>>()
        );
        assert!(summary_of(&signed).is_empty(), "nothing held back");
        // a thousand held programs outliving, a thousand unseen and
        // baseline ones held: each named, and a flood of plain unseen
        // ones still under its own quota
        let mut found: Vec<Finding> = (1..=1_000)
            .map(|id| Finding::Bpf(B::HeldOutlived(held(id), 0x0b_0000_0002)))
            .collect();
        found.extend((2_001..=2_100).map(|id| Finding::Bpf(B::Unseen(held(id)))));
        found.extend((3_001..=3_100).map(|id| Finding::Bpf(B::Baseline(held(id)))));
        found.extend((4_001..=4_100).map(|id| unseen(id, 1)));
        let (signed, held_back) = one_round(found);
        assert_eq!(held_back.len(), 100 - ROUND_QUOTA);
        assert!(held_back
            .iter()
            .all(|f| matches!(f, Finding::Bpf(B::Unseen(o)) if o.held.is_none())));
        assert_eq!(ids(&signed).len(), 1_000 + 100 + 100 + ROUND_QUOTA);
        for f in [
            Finding::Bpf(B::HeldOutlived(object(9, 2), 0)),
            Finding::Bpf(B::Unseen(held(9))),
            Finding::Bpf(B::Baseline(held(9))),
        ] {
            assert_eq!(Kind::of(&f), None, "{f:?} under the quota");
        }
        assert!(!Kind::ALL.iter().any(|k| k.name().contains("outlived")));
    }

    /// The re-check of #565 (R1): the cross-view marks each finding about a
    /// program the round's held set has with its held load's verdict —
    /// links and the programs not held are left as they are.
    #[test]
    fn the_cross_view_marks_a_held_program_s_findings_held() {
        use crate::bpf_crossview::{mark_held, Finding as B, Object};
        let mut found = vec![
            B::Unseen(object(5, 1)),
            B::Baseline(object(6, 2)),
            B::Unseen(Object {
                is_link: true,
                ..object(5, 1)
            }),
            B::HeldOutlived(object(7, 2), 9),
        ];
        mark_held(&mut found, &[(5, 0x0b_0000_0001), (7, 9)]);
        let held: Vec<Option<u64>> = found
            .iter()
            .map(|f| {
                let (B::Unseen(o) | B::Baseline(o) | B::HeldOutlived(o, _)) = f;
                o.held
            })
            .collect();
        assert_eq!(held, vec![Some(0x0b_0000_0001), None, None, Some(9)]);
    }

    /// The review of #565 (F2): under the quota the most dangerous are
    /// named first — a kprobe loaded last among a thousand socket filters,
    /// and a link whose program the enumeration does not show, are signed
    /// by name; a proven known system program is the first held back.
    #[test]
    fn a_flood_of_socket_filters_never_hides_a_kprobe_under_the_quota() {
        use crate::bpf_crossview::Finding as B;
        let mut found: Vec<Finding> = (1..=1_000).map(|id| unseen(id, 1)).collect();
        found.push(unseen(5_000, 2)); // BPF_PROG_TYPE_KPROBE
                                      // a link (type 1, raw_tracepoint) whose program is hidden: named
                                      // for being a link, whatever its type
        found.push(Finding::Bpf(B::Unseen(crate::bpf_crossview::Object {
            is_link: true,
            ..object(6_000, 1)
        })));
        let (signed, _) = one_round(found);
        let named = ids(&signed);
        assert!(
            named.contains(&(false, 5_000)),
            "the kprobe held back: {named:?}"
        );
        assert!(
            named.contains(&(true, 6_000)),
            "the hidden program's link held back"
        );
        assert_eq!(named.len(), ROUND_QUOTA);
        // the baseline: a proven known program after the unknown ones
        let mut base: Vec<Finding> = (1..=ROUND_QUOTA as u32)
            .map(|id| Finding::Bpf(B::Baseline(object(id, 1))))
            .collect();
        base.insert(
            0,
            Finding::Bpf(B::Baseline(crate::bpf_crossview::Object {
                known: Some((1, 0)),
                ..object(999, 29)
            })),
        );
        let (signed, held) = one_round(base);
        assert_eq!(held.len(), 1);
        // one held back is one summary, counting it
        let s = summary_of(&signed);
        assert_eq!((s.len(), s[0].baseline, s[0].total()), (1, 1, 1));
        assert_eq!(
            match &held[0] {
                Finding::Bpf(b) => b.object(),
                _ => (true, 0),
            },
            (false, 999)
        );
    }

    /// The re-check of #565 (R2): an XDP program loaded among a thousand
    /// socket filters shared their rank and was held back — the summary
    /// named no object, and no later round named it. A BPF object is
    /// ranked by what it can do: the XDP is named the round it is found;
    /// so are tc, kprobe, fentry, LSM, struct_ops and syscall programs and
    /// an fmod_ret; a held program and a link whose program is hidden
    /// before them; socket filters and cgroup_skb last.
    #[test]
    fn an_xdp_among_a_thousand_socket_filters_is_named_the_round_it_is_found() {
        use crate::bpf_crossview::{Finding as B, Object};
        // the probe of the re-check
        let mut found: Vec<Finding> = (1..=1_000).map(|id| unseen(id, 1)).collect();
        found.push(unseen(5_000, 6)); // BPF_PROG_TYPE_XDP
        let (signed, held) = one_round(found);
        assert!(
            ids(&signed).contains(&(false, 5_000)),
            "the XDP held back: {:?}",
            ids(&signed)
        );
        assert!(!held
            .iter()
            .any(|f| matches!(f, Finding::Bpf(b) if b.object() == (false, 5_000))));
        // each type of wide reach among a thousand socket filters and
        // cgroup_skb programs (the rank is the type's, the id last)
        let wide = [
            (6_000, 6),  // xdp
            (6_001, 3),  // sched_cls
            (6_002, 4),  // sched_act
            (6_003, 2),  // kprobe
            (6_004, 26), // tracing (fentry)
            (6_005, 29), // lsm
            (6_006, 27), // struct_ops
            (6_007, 31), // syscall
            (6_008, 5),  // tracepoint
        ];
        let mut found: Vec<Finding> = (1..=500).map(|id| unseen(id, 1)).collect();
        found.extend((501..=1_000).map(|id| unseen(id, 8)));
        found.extend(wide.iter().map(|(id, t)| unseen(*id, *t)));
        // a cgroup_sock_addr (another type), an fmod_ret, a held one, a
        // link whose program is hidden
        found.push(unseen(7_000, 18));
        found.push(Finding::Bpf(B::Unseen(Object {
            attach_type: common::bpf_prog_class::ATTACH_MODIFY_RETURN,
            ..object(7_001, 26)
        })));
        found.push(Finding::Bpf(B::Unseen(Object {
            is_link: true,
            ..object(7_002, 1)
        })));
        let (signed, _) = one_round(found);
        let named = ids(&signed);
        for (id, _) in wide {
            assert!(named.contains(&(false, id)), "{id} held back: {named:?}");
        }
        for key in [(false, 7_000), (false, 7_001), (true, 7_002)] {
            assert!(named.contains(&key), "{key:?} held back: {named:?}");
        }
        assert_eq!(named.len(), ROUND_QUOTA);
        // the ranks themselves, most dangerous first
        let o = |t: u32| Finding::Bpf(B::Unseen(object(1, t)));
        let r = |f: Finding| rank(&f);
        let held_one = Finding::Bpf(B::Unseen(Object {
            held: Some(1),
            ..object(1, 1)
        }));
        let fmod_ret = Finding::Bpf(B::Unseen(Object {
            attach_type: common::bpf_prog_class::ATTACH_MODIFY_RETURN,
            ..object(1, 26)
        }));
        assert_eq!(r(held_one), r(fmod_ret.clone()));
        assert!(r(fmod_ret) < r(o(6)));
        for (wide, other) in [(6, 18), (3, 18), (2, 18), (31, 18), (29, 15)] {
            assert!(r(o(wide)) < r(o(other)), "{wide} {other}");
        }
        for low in [1, 8] {
            assert!(r(o(18)) < r(o(low)), "{low}");
            assert!(r(o(99)) < r(o(low)), "an unknown type below a filter");
        }
        let kernel_s = Finding::Bpf(B::Unseen(Object {
            early: true,
            ..object(1, 2)
        }));
        assert_eq!(r(kernel_s), r(o(18)), "the kernel's own kprobe");
        let known = Finding::Bpf(B::Baseline(Object {
            known: Some((1, 0)),
            ..object(1, 29)
        }));
        assert!(r(o(1)) < r(known));
    }

    /// The re-check of #565 (R2): the summary carried only counts — no
    /// object, no id, no type. It names, per kind, the highest-ranked held
    /// back and the first and the last in the round's order (id and type).
    #[test]
    fn the_summary_names_each_kind_s_highest_ranked_first_and_last_held_back() {
        use crate::bpf_crossview::{Finding as B, Object};
        let mut found: Vec<Finding> = (1..=1_000).map(|id| unseen(id, 1)).collect();
        // under the quota's 32 kprobes, one cgroup_sock_addr: the highest
        // ranked held back
        found.extend((2_001..=2_032).map(|id| unseen(id, 2)));
        found.push(unseen(3_000, 18));
        found.push(Finding::Bpf(B::Baseline(Object {
            is_link: true,
            ..object(9, 2)
        })));
        found.extend((10..=50).map(|id| Finding::Bpf(B::Baseline(object(id, 8)))));
        found.extend((800..=840).map(Finding::RootProgram));
        let (signed, held) = one_round(found);
        let named = named_of(&signed);
        assert_eq!(
            named,
            "bpf_unseen 1001 top=prog:3000:cgroup_sock_addr first=prog:1:socket_filter \
             last=prog:3000:cgroup_sock_addr; bpf_baseline 10 top=prog:41:cgroup_skb \
             first=prog:41:cgroup_skb last=prog:50:cgroup_skb; sysctl_root_prog 9 \
             top=prog:832:cgroup_sysctl first=prog:832:cgroup_sysctl \
             last=prog:840:cgroup_sysctl"
        );
        assert_eq!(held.len(), 1_001 + 10 + 9);
        // the link is named (a hidden program first), the cgroup_skb ones
        // after it in the round's order
        assert!(ids(&signed).contains(&(true, 9)));
        // what it names cannot spill into the next field
        let c = Finding::Cpus(crate::own_cpus::Confinement {
            left: vec![0],
            expected: vec![0, 1],
            cause: crate::own_cpus::Cause::CgroupCpuset("/a b;c".into(), vec![0]),
        });
        assert!(!named_as(&c).contains([' ', ';']), "{}", named_as(&c));
        assert_eq!(named_as(&unseen(4, 99)), "prog:4:type_99");
    }

    /// The re-check of #565 (R2): a finding the quota held back was never
    /// named after — the cross-view signs an object once, before the quota.
    /// What a round holds back is carried into the next, first in its rank,
    /// until a round names it: a thousand socket filters are each named
    /// exactly once, 32 a round; an XDP found meanwhile is named the round
    /// it comes; each summary says how many it counts were carried; the
    /// carry is bounded, the highest-ranked kept.
    #[test]
    fn what_a_round_held_back_is_named_by_a_later_round_once() {
        let mut q = Quota::default();
        let mut named: Vec<(bool, u32)> = Vec::new();
        let w = q.apply((1..=1_000).map(|id| unseen(id, 1)).collect(), ROUND_QUOTA);
        named.extend(ids(&w.signed));
        assert_eq!((w.again, w.held.len()), (0, 1_000 - ROUND_QUOTA));
        assert_eq!(q.carried().len(), 1_000 - ROUND_QUOTA);
        // the next round: an XDP comes, named at once; the carried first
        let w = q.apply(vec![unseen(5_000, 6)], ROUND_QUOTA);
        let now = ids(&w.signed);
        assert!(now.contains(&(false, 5_000)), "{now:?}");
        assert_eq!(
            now[..ROUND_QUOTA - 1],
            (33..33 + ROUND_QUOTA as u32 - 1)
                .map(|id| (false, id))
                .collect::<Vec<_>>()[..]
        );
        assert_eq!(w.again, 1_000 - ROUND_QUOTA - (ROUND_QUOTA - 1));
        let s = summary_of(&w.signed)[0];
        assert_eq!(u64::from(s.carried), s.total(), "every one held carried");
        named.extend(now);
        let mut rounds = 2;
        while !q.carried().is_empty() {
            let w = q.apply(Vec::new(), ROUND_QUOTA);
            named.extend(ids(&w.signed));
            rounds += 1;
            assert!(rounds < 40, "never all named");
        }
        named.sort_unstable();
        let mut want: Vec<(bool, u32)> = (1..=1_000).map(|id| (false, id)).collect();
        want.push((false, 5_000));
        assert_eq!(named, want, "each named exactly once");
        assert_eq!(rounds, 1_001usize.div_ceil(ROUND_QUOTA));
        // the carry is bounded: past it the highest-ranked are kept
        let mut q = Quota::default();
        let mut flood: Vec<Finding> = (1..=CARRY_MAX as u32 + 500)
            .map(|id| unseen(id, 1))
            .collect();
        flood.extend((100_001..=100_000 + ROUND_QUOTA as u32 + 5).map(|id| unseen(id, 18)));
        q.apply(flood, ROUND_QUOTA);
        assert_eq!(q.carried().len(), CARRY_MAX);
        let carried = ids(q.carried());
        for id in 100_001 + ROUND_QUOTA as u32..=100_000 + ROUND_QUOTA as u32 + 5 {
            assert!(carried.contains(&(false, id)), "{id} not carried");
        }
        assert!(
            !carried.contains(&(false, CARRY_MAX as u32 + 500)),
            "the lowest-ranked last kept"
        );
        // the mini-hunt: every kind is carried — the root's 64 cgroup/sysctl
        // programs are all named by the second round, each once
        let mut q = Quota::default();
        let w = q.apply((1..=64).map(Finding::RootProgram).collect(), ROUND_QUOTA);
        let first: Vec<&Finding> = w
            .signed
            .iter()
            .filter(|f| matches!(f, Finding::RootProgram(_)))
            .collect();
        assert_eq!(first.len(), ROUND_QUOTA);
        let w = q.apply(Vec::new(), ROUND_QUOTA);
        assert_eq!(
            w.signed,
            (ROUND_QUOTA as u32 + 1..=64)
                .map(Finding::RootProgram)
                .collect::<Vec<_>>()
        );
        assert!(q.carried().is_empty());
    }
}
