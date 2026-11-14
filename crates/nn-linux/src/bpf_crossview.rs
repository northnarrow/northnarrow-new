//! Lot 290: the light cross-view of the host's BPF programs and links.
//!
//! Every kernel-state round (5 s) the agent enumerates the programs and the
//! links loaded on the host — with its own BPF iterators
//! (`agent-ebpf/src/bpf_census.rs`): the unit has no `CAP_SYS_ADMIN`, which
//! `BPF_*_GET_NEXT_ID` needs — and compares them with what its `bpf` hook
//! saw loading since its start (`SEEN_PROGS`, filled by the `bpf_prog`
//! hook for every load the `bpf` hook let through).
//!
//! * An object that is neither the agent's own nor seen loading, present
//!   at the first enumeration after the start, is the **baseline**: loaded
//!   while the agent was not running (at boot before it, in a restart's or
//!   an upgrade's gap). Each is signed once (`FsProtectOperation::
//!   BpfBaseline`: Low, High for a type refused outside a window).
//! * One that appears later and that the hook never saw is **unseen**:
//!   loaded through a path the hook does not see, or hidden from it — a
//!   signed High (`FsProtectOperation::BpfUnseen`) with its type, name, tag
//!   and attach point.
//! * An object is judged only once it is in two enumerations in a row (a
//!   round apart): a program of the agent's prior run whose release is
//!   still pending, or one whose load is recorded between the two reads, is
//!   not a finding. A program that lives less than a round is not seen
//!   here at all — the light part of the cross-view.
//! * A link is judged through its program; a link whose program the
//!   program enumeration does not show (hidden from it) is judged itself.
//!
//! Each round also writes the foreign objects and what the agent knows of
//! them to [`STATUS_FILE_NAME`] (next to the agent's pid file): the host's
//! inventory of foreign BPF, and who loaded what since the start.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use aya::maps::{HashMap, MapData};
use aya::{Btf, Ebpf};
use common::bpf_prog_class::{
    attach_type_name, link_type_name, prog_type_name, tag_word, text, LinkRecord, ProgRecord,
    SeenLoad, ATTACH_TRACE_ITER,
};

/// The program iterator's program in the eBPF object.
pub const ITER_PROGS: &str = "census_progs";
/// The link iterator's program (kernels with `bpf_iter_bpf_link`).
pub const ITER_LINKS: &str = "census_links";
/// The map of the programs the hook saw loading.
pub const SEEN_MAP: &str = "SEEN_PROGS";
/// Lot 349 (the review of #558, F5): the map of the programs held at a
/// window's load (`agent-ebpf`'s `PROG_CONTENT_HELD`, pinned), whose ids no
/// longer loaded each round removes.
pub const HELD_MAP: &str = "PROG_CONTENT_HELD";
/// The status file's name, beside the agent's pid file.
pub const STATUS_FILE_NAME: &str = "bpf-foreign";
/// The signed degradation's source while the cross-view does not run.
pub const DEGRADATION: &str = "bpf_crossview";

/// aya view of [`SeenLoad`].
#[repr(transparent)]
#[derive(Clone, Copy)]
struct AyaSeen(SeenLoad);

// SAFETY: `SeenLoad` is `#[repr(C)]` over four u32 and [u8; 16] — no padding,
// every bit pattern valid; `AyaSeen` is `#[repr(transparent)]`.
unsafe impl aya::Pod for AyaSeen {}

/// `BPF_LINK_CREATE`'s head of `union bpf_attr` (the iterator's info left
/// zero: the program and link iterators take none).
#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
}

/// `BPF_ITER_CREATE`'s `union bpf_attr`.
#[repr(C)]
struct IterCreateAttr {
    link_fd: u32,
    flags: u32,
}

fn sys_bpf<T>(cmd: u32, attr: &mut T) -> std::io::Result<OwnedFd> {
    // SAFETY: `attr` is a fully initialised `#[repr(C)]` head of `union
    // bpf_attr` and its exact size is passed (the kernel zero-fills the
    // rest); the fd returned is owned here only.
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr as *mut T as *mut libc::c_void,
            std::mem::size_of::<T>() as u32,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: a fresh descriptor the kernel just returned.
        Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
    }
}

/// The cross-view's kernel parts: the two iterators' links and the seen
/// map, taken from the eBPF object at the attach.
pub struct Parts {
    progs: OwnedFd,
    links: Option<OwnedFd>,
    seen: HashMap<MapData, u32, AyaSeen>,
    /// `None`: an object without it (the eBPF object of an older build).
    held: Option<HashMap<MapData, u32, u64>>,
}

/// Load iterator program `name` on `target` (`bpf_prog`, `bpf_link`) and
/// make its link.
fn load_iter(ebpf: &mut Ebpf, name: &str, target: &str, btf: &Btf) -> Result<OwnedFd, String> {
    let prog: &mut aya::programs::Iter = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("{name} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{name} is not an iterator: {e}"))?;
    prog.load(target, btf)
        .map_err(|e| format!("{name} (iter/{target}): {e:#}"))?;
    let fd = prog
        .fd()
        .map_err(|e| format!("{name}: {e}"))?
        .as_fd()
        .as_raw_fd();
    let mut attr = LinkCreateAttr {
        prog_fd: fd as u32,
        target_fd: 0,
        attach_type: ATTACH_TRACE_ITER,
        flags: 0,
    };
    sys_bpf(common::bpf_cmd::BPF_LINK_CREATE, &mut attr)
        .map_err(|e| format!("{name}: BPF_LINK_CREATE: {e}"))
}

impl Parts {
    /// The iterators loaded and linked, the seen map taken. The link
    /// iterator is optional (kernels before it: programs only).
    pub fn setup(ebpf: &mut Ebpf, btf: &Btf) -> Result<Parts, String> {
        let progs = load_iter(ebpf, ITER_PROGS, "bpf_prog", btf)?;
        let links = match load_iter(ebpf, ITER_LINKS, "bpf_link", btf) {
            Ok(l) => Some(l),
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "BPF cross-view: no link iterator on this kernel — programs enumerated only"
                );
                None
            }
        };
        let seen = ebpf
            .take_map(SEEN_MAP)
            .ok_or_else(|| format!("{SEEN_MAP} missing from the eBPF object"))?;
        let seen: HashMap<MapData, u32, AyaSeen> =
            HashMap::try_from(seen).map_err(|e| format!("{SEEN_MAP}: {e}"))?;
        let held = match ebpf.take_map(HELD_MAP).map(HashMap::try_from) {
            Some(Ok(m)) => Some(m),
            Some(Err(e)) => return Err(format!("{HELD_MAP}: {e}")),
            None => None,
        };
        Ok(Parts {
            progs,
            links,
            seen,
            held,
        })
    }

    /// Lot 349 (the review of #558, F5): the ids held now, each with the
    /// judge's verdict at its load (`why << 32 | type`).
    pub fn held(&self) -> Vec<(u32, u64)> {
        match &self.held {
            Some(m) => m.iter().filter_map(Result::ok).collect(),
            None => Vec::new(),
        }
    }

    /// Lot 349 (the review of #558, F5): remove `ids` from the held map
    /// (programs freed since); how many went.
    pub fn release_held(&mut self, ids: &[u32]) -> usize {
        let Some(m) = &mut self.held else {
            return 0;
        };
        ids.iter().filter(|id| m.remove(id).is_ok()).count()
    }

    /// One enumeration: every program, and every link where the kernel has
    /// the link iterator.
    pub fn enumerate(&self) -> Result<Enumeration, String> {
        let progs = records::<ProgRecord>(&read_iter(&self.progs)?);
        let links = match &self.links {
            Some(l) => Some(records::<LinkRecord>(&read_iter(l)?)),
            None => None,
        };
        Ok(Enumeration { progs, links })
    }

    /// What the hook saw loading, as the kernel holds it now.
    pub fn seen(&self) -> Result<Vec<(u32, SeenLoad)>, String> {
        Ok(self
            .seen
            .iter()
            .filter_map(Result::ok)
            .map(|(k, v)| (k, v.0))
            .collect())
    }
}

/// Every byte one iteration of `link` writes.
fn read_iter(link: &OwnedFd) -> Result<Vec<u8>, String> {
    let mut attr = IterCreateAttr {
        link_fd: link.as_raw_fd() as u32,
        flags: 0,
    };
    let fd = sys_bpf(common::bpf_cmd::BPF_ITER_CREATE, &mut attr)
        .map_err(|e| format!("BPF_ITER_CREATE: {e}"))?;
    let mut out = Vec::new();
    File::from(fd)
        .read_to_end(&mut out)
        .map_err(|e| format!("reading the iterator: {e}"))?;
    Ok(out)
}

/// The fixed-size records of `bytes` (a trailing partial record dropped).
fn records<T: bytemuck::Pod>(bytes: &[u8]) -> Vec<T> {
    bytes
        .chunks_exact(std::mem::size_of::<T>())
        .map(bytemuck::pod_read_unaligned::<T>)
        .collect()
}

/// One enumeration.
#[derive(Debug, Clone, Default)]
pub struct Enumeration {
    pub progs: Vec<ProgRecord>,
    /// `None`: the kernel has no link iterator.
    pub links: Option<Vec<LinkRecord>>,
}

/// An object the cross-view signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub is_link: bool,
    pub id: u32,
    /// The program's type, or the link's.
    pub object_type: u32,
    pub name: String,
    /// The program's tag (`tag_word`), 0 for a link.
    pub tag: u64,
    /// Where it is attached: the attach function, else the link types of
    /// its links, else its expected attach type (when it has one).
    pub attach: String,
    /// The kernel's own: loaded before user space started (its load time
    /// before PID 1's start), or one of the programs the kernel loads from a
    /// module's init (`common::bpf_prog_class::KERNEL_PROGRAMS`: HID-BPF's
    /// `hid_tail_call` on its attach function).
    pub early: bool,
    /// Lot 304: a baseline program proven a known system program
    /// ([`crate::known_system_prog`]): its loader's pid and uid.
    pub known: Option<(u32, u32)>,
}

/// A finding to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Present at the start, never seen loading: signed once.
    Baseline(Object),
    /// Appeared later, never seen loading.
    Unseen(Object),
    /// Lot 349 (the re-check of #558, item 2): a program held at a
    /// trusted-installer window's load (its verdict, `why << 32 | type`)
    /// still loaded after the window — attached, pinned or kept by a
    /// descriptor: signed once.
    HeldOutlived(Object, u64),
}

/// What the cross-view keeps between rounds.
#[derive(Debug, Default)]
pub struct Watch {
    rounds: u32,
    /// The candidates of the first enumeration (the start's baseline).
    first: BTreeSet<(bool, u32)>,
    /// Candidates seen in the last enumeration, not judged yet.
    pending: BTreeSet<(bool, u32)>,
    /// Objects signed (baseline or unseen).
    signed: BTreeSet<(bool, u32)>,
    /// Every program the hook saw loading since the start (the kernel's
    /// map is LRU: what was copied here stays).
    seen: BTreeMap<u32, SeenLoad>,
    /// When user space started (PID 1's start, boot-time ns): a program
    /// loaded before it is the kernel's own.
    pub user_space_since: Option<u64>,
    /// Lot 304: the programs of the last enumeration, by id (the
    /// kernel-state round tells a root `cgroup/sysctl` program by them).
    progs: BTreeMap<u32, ProgRecord>,
    /// Lot 349 (the re-check of #558, item 2): the held programs signed
    /// as outliving their window.
    outlived: BTreeSet<u32>,
}

/// Lot 304: what the known-program judgement reads of a record — its
/// type, name, attach function (when read) and load time.
pub fn program_of(p: &ProgRecord) -> crate::known_system_prog::Program {
    crate::known_system_prog::Program {
        prog_type: p.prog_type,
        name: text(&p.name),
        attach: if p.attach_read == 1 {
            text(&p.attach)
        } else {
            String::new()
        },
        load_time: p.load_time,
    }
}

/// A program record's attach point.
fn attach_of(p: &ProgRecord, link_types: &BTreeMap<u32, BTreeSet<String>>) -> String {
    if p.attach_read == 1 {
        let a = text(&p.attach);
        if !a.is_empty() {
            return a;
        }
    }
    match link_types.get(&p.id) {
        Some(t) if !t.is_empty() => t.iter().cloned().collect::<Vec<_>>().join("+"),
        // 0 is also "none given" (a cgroup program attached the legacy way
        // says nothing of where): not named
        _ if p.expected_attach_type == 0 => "unknown (no link, no attach type)".to_string(),
        _ => attach_type_name(p.expected_attach_type),
    }
}

/// When user space started: PID 1's start in `/proc/1/stat` (field 22,
/// clock ticks since boot), in boot-time ns — the clock of a program's
/// `load_time`.
pub fn user_space_start_ns(stat: &str, clk_tck: u64) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    let ticks: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    (clk_tck > 0).then(|| ticks.saturating_mul(1_000_000_000) / clk_tck)
}

/// [`user_space_start_ns`] of this host.
pub fn host_user_space_start_ns() -> Option<u64> {
    // the re-check of #558 (F7): within the round's deadline
    let stat = crate::state_read::ROUND_READER
        .read_state("/proc/1/stat")
        .ok()?;
    // SAFETY: sysconf has no preconditions.
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    user_space_start_ns(&stat, u64::try_from(tck).ok()?)
}

impl Watch {
    /// A watch that tells the kernel's own programs by `user_space_since`.
    pub fn new(user_space_since: Option<u64>) -> Self {
        Self {
            user_space_since,
            ..Self::default()
        }
    }

    /// The programs seen loading so far, with their loaders.
    pub fn seen(&self) -> &BTreeMap<u32, SeenLoad> {
        &self.seen
    }

    /// Lot 304: program `id` as the last enumeration had it — its type,
    /// name and load time.
    pub fn program(&self, id: u32) -> Option<crate::known_system_prog::Program> {
        self.progs.get(&id).map(program_of)
    }

    /// Enumerations done.
    pub fn rounds(&self) -> u32 {
        self.rounds
    }

    /// The state the status file names an object by.
    pub fn state_of(&self, key: (bool, u32)) -> &'static str {
        if !key.0 && self.seen.contains_key(&key.1) {
            "seen"
        } else if self.signed.contains(&key) && self.first.contains(&key) {
            "baseline"
        } else if self.signed.contains(&key) {
            "unseen"
        } else {
            "pending"
        }
    }
}

/// One round: `seen_now` (the hook's map, read before the enumeration),
/// `en` the enumeration, `own` the agent's program ids. The findings to
/// sign, and the foreign objects of this round (for the status file).
pub fn judge(
    w: &mut Watch,
    seen_now: Vec<(u32, SeenLoad)>,
    en: &Enumeration,
    own: &BTreeSet<u32>,
) -> (Vec<Finding>, Vec<Object>) {
    w.seen.extend(seen_now);
    w.progs = en.progs.iter().map(|p| (p.id, *p)).collect();
    let mut link_types: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for l in en.links.iter().flatten() {
        link_types
            .entry(l.prog_id)
            .or_default()
            .insert(link_type_name(l.link_type));
    }
    let listed: BTreeSet<u32> = en.progs.iter().map(|p| p.id).collect();
    let mut foreign: Vec<Object> = Vec::new();
    for p in en.progs.iter().filter(|p| !own.contains(&p.id)) {
        foreign.push(Object {
            is_link: false,
            id: p.id,
            object_type: p.prog_type,
            name: text(&p.name),
            tag: tag_word(p.tag),
            attach: attach_of(p, &link_types),
            early: (p.load_time != 0 && w.user_space_since.is_some_and(|t| p.load_time < t))
                || (p.attach_read == 1
                    && common::bpf_prog_class::is_kernel_program(&p.name, &p.attach)),
            known: None,
        });
    }
    // a link is judged through its program; one whose program the program
    // enumeration does not show is judged itself (0: a detached link)
    for l in en.links.iter().flatten() {
        if l.prog_id == 0 || own.contains(&l.prog_id) || listed.contains(&l.prog_id) {
            continue;
        }
        foreign.push(Object {
            is_link: true,
            id: l.id,
            object_type: l.link_type,
            name: String::new(),
            tag: 0,
            attach: format!("program {} not enumerated", l.prog_id),
            early: false,
            known: None,
        });
    }
    let candidates: BTreeMap<(bool, u32), &Object> = foreign
        .iter()
        .filter(|o| o.is_link || !w.seen.contains_key(&o.id))
        .map(|o| ((o.is_link, o.id), o))
        .collect();
    if w.rounds == 0 {
        w.first = candidates.keys().copied().collect();
    }
    let mut out = Vec::new();
    // a key signed once is never pending again (below): signed once
    for (key, o) in &candidates {
        if w.pending.contains(key) {
            w.signed.insert(*key);
            out.push(if w.first.contains(key) {
                Finding::Baseline((*o).clone())
            } else {
                Finding::Unseen((*o).clone())
            });
        }
    }
    w.pending = candidates
        .keys()
        .filter(|k| !w.signed.contains(k))
        .copied()
        .collect();
    w.rounds += 1;
    (out, foreign)
}

/// Lot 349 (the re-check of #558, item 2): the held programs (`held`, read
/// before the enumeration) that the enumeration still shows (`foreign`)
/// while no window is open — each signed once ([`Finding::HeldOutlived`]):
/// a program loaded inside the window that outlives it (attached by a link
/// made inside it, pinned, kept by a descriptor) is never left unseen, and
/// a later window's close does not sign it again. Inside a window nothing
/// is signed (what an installer loads runs there by design).
pub fn outlived(
    w: &mut Watch,
    held: &[(u32, u64)],
    foreign: &[Object],
    window_open: bool,
) -> Vec<Finding> {
    w.outlived
        .retain(|id| held.iter().any(|(h, _)| h == id));
    if window_open {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (id, verdict) in held {
        let Some(o) = foreign.iter().find(|o| !o.is_link && o.id == *id) else {
            continue;
        };
        if w.outlived.insert(*id) {
            out.push(Finding::HeldOutlived(o.clone(), *verdict));
        }
    }
    out
}

/// The status file's body: one line per foreign object.
pub fn render_status(w: &Watch, foreign: &[Object]) -> String {
    let mut body = format!(
        "# northnarrow-agent pid {}: foreign BPF objects at enumeration {} (kind id type name tag \
         attach state [loader])\n",
        std::process::id(),
        w.rounds()
    );
    for o in foreign {
        let (kind, t) = if o.is_link {
            ("link", link_type_name(o.object_type))
        } else {
            ("prog", prog_type_name(o.object_type))
        };
        let state = w.state_of((o.is_link, o.id));
        let loader = if o.is_link {
            String::new()
        } else {
            w.seen()
                .get(&o.id)
                .map(|s| format!(" pid={} uid={} comm={}", s.tgid, s.uid, text(&s.comm)))
                .unwrap_or_default()
        };
        body.push_str(&format!(
            "{kind} {} {t} {} {:016x} {} {state}{}{loader}\n",
            o.id,
            if o.name.is_empty() { "-" } else { &o.name },
            o.tag,
            o.attach.replace(' ', "_"),
            if o.early { " kernel" } else { "" },
        ));
    }
    // every load the hook saw since the start, gone or not: the host's
    // loaders and their types (the agent's own loads left out)
    let me = std::process::id();
    for (id, l) in w.seen().iter().filter(|(_, l)| l.tgid != me) {
        body.push_str(&format!(
            "load {id} {} pid={} uid={} comm={}\n",
            prog_type_name(l.prog_type),
            l.tgid,
            l.uid,
            text(&l.comm)
        ));
    }
    body
}

/// The cross-view as the kernel-state round runs it.
pub struct CrossView {
    pub parts: Parts,
    /// The agent's own program ids (both registrations).
    pub own: Box<dyn Fn() -> BTreeSet<u32> + Send>,
    /// Where the status file goes (`None`: not written).
    pub status: Option<PathBuf>,
    pub watch: Watch,
    /// Lot 349 (the re-check of #558, item 2): a trusted-installer window is
    /// open now.
    pub window_open: Box<dyn Fn() -> bool + Send>,
}

impl CrossView {
    /// One round: the findings to sign. An error stops nothing: the round
    /// says it (a signed degradation while it holds).
    pub fn round(&mut self) -> Result<Vec<Finding>, String> {
        let seen = self.parts.seen()?;
        // the held ids read BEFORE the enumeration: one held after it is
        // newer than it, and stays
        let held = self.parts.held();
        let en = self.parts.enumerate()?;
        let ids: Vec<u32> = held.iter().map(|(id, _)| *id).collect();
        let gone = stale_held(&ids, &en.progs);
        if !gone.is_empty() {
            let n = self.parts.release_held(&gone);
            tracing::debug!(
                released = n,
                "BPF self-defence: held programs no longer loaded released"
            );
        }
        let mut own = (self.own)();
        // the agent's own loads not registered yet (a sensor attached after
        // the registration, until the late one: the lab's 22.04 round saw
        // the exploit guard's programs so for a round)
        let me = std::process::id();
        own.extend(seen.iter().filter(|(_, l)| l.tgid == me).map(|(id, _)| *id));
        own.extend(
            self.watch
                .seen()
                .iter()
                .filter(|(_, l)| l.tgid == me)
                .map(|(id, _)| *id),
        );
        let (mut found, foreign) = judge(&mut self.watch, seen, &en, &own);
        // the window's state read after the enumeration: a held id read
        // before it was loaded inside a window that has ended by now
        found.extend(outlived(
            &mut self.watch,
            &held,
            &foreign,
            (self.window_open)(),
        ));
        if let Some(path) = &self.status {
            let body = render_status(&self.watch, &foreign);
            if let Err(e) = crate::atomic_file::replace(path, body.as_bytes(), 0o600) {
                tracing::debug!(error = %e, path = %path.display(), "BPF cross-view: status file not written");
            }
        }
        Ok(found)
    }
}

/// Lot 349 (the review of #558, F5): of the ids held before an enumeration
/// (`held`), those it no longer shows — programs freed since their window's
/// load, whose entries would otherwise fill the held set (1024 ids, never
/// emptied: full, a window's forbidden load is refused). Prog ids are
/// cyclic (`idr_alloc_cyclic`): a freed id comes back only after 2^31
/// loads, so a stale entry was never a false refusal, only a full set. An
/// id held after the enumeration is not in `held` and stays.
pub fn stale_held(held: &[u32], progs: &[ProgRecord]) -> Vec<u32> {
    let live: BTreeSet<u32> = progs.iter().map(|p| p.id).collect();
    held.iter()
        .copied()
        .filter(|id| !live.contains(id))
        .collect()
}

/// The status file's path for an agent whose pid file is `pid_file`.
pub fn status_path(beside: &Path) -> PathBuf {
    beside
        .parent()
        .unwrap_or_else(|| Path::new("/run/northnarrow"))
        .join(STATUS_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog(id: u32, t: u32, name: &str) -> ProgRecord {
        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name.as_bytes());
        ProgRecord {
            id,
            prog_type: t,
            expected_attach_type: 6,
            attach_read: 0,
            load_time: 9_000_000_000,
            tag: [0xab, 0, 0, 0, 0, 0, 0, id as u8],
            name: n,
            attach: [0u8; 64],
        }
    }

    /// Lot 349 (the review of #558, F5): the held set was never emptied — a
    /// window holder's 1024 tiny forbidden loads, freed at once, filled it
    /// for the agent's life. The round releases every held id the
    /// enumeration no longer shows, and only those.
    #[test]
    fn held_programs_no_longer_loaded_are_released_each_round() {
        let live = [prog(7, 2, "a"), prog(9, 26, "b")];
        assert_eq!(stale_held(&[7, 8, 9, 1024], &live), vec![8, 1024]);
        assert!(
            stale_held(&[7, 9], &live).is_empty(),
            "loaded ones stay held"
        );
        assert!(stale_held(&[], &live).is_empty());
        assert_eq!(
            stale_held(&[3], &[]),
            vec![3],
            "nothing loaded: all released"
        );
    }

    /// Lot 349 (the re-check of #558, item 2): a held program attached by a
    /// link made inside the window ran unseen after it — only its load was
    /// signed. Once no window is open, each held program still loaded is
    /// signed once (not inside a window, not again at a later window's
    /// close, not when it is no longer loaded).
    #[test]
    fn a_held_program_still_loaded_after_its_window_is_signed_once() {
        let mut w = Watch::default();
        let en = Enumeration {
            progs: vec![prog(7, 2, "k349_sig"), prog(9, 26, "b")],
            links: Some(vec![LinkRecord {
                id: 40,
                prog_id: 7,
                link_type: 2,
                _pad: 0,
            }]),
        };
        let (_, foreign) = judge(&mut w, Vec::new(), &en, &BTreeSet::new());
        let held = [(7, 0x0b_0000_0002), (8, 1)];
        assert!(
            outlived(&mut w, &held, &foreign, true).is_empty(),
            "inside the window: nothing"
        );
        let found = outlived(&mut w, &held, &foreign, false);
        assert_eq!(found.len(), 1, "{found:?}");
        let Finding::HeldOutlived(o, verdict) = &found[0] else {
            panic!("{found:?}");
        };
        assert_eq!((o.id, *verdict), (7, 0x0b_0000_0002));
        assert_eq!(o.attach, link_type_name(2), "its link named");
        assert!(
            outlived(&mut w, &held, &foreign, false).is_empty(),
            "signed once"
        );
        assert!(outlived(&mut w, &held, &foreign, true).is_empty());
        assert!(
            outlived(&mut w, &held, &foreign, false).is_empty(),
            "a later window's close: not again"
        );
        // released from the held set: forgotten
        assert!(outlived(&mut w, &[], &foreign, false).is_empty());
        assert_eq!(w.outlived.len(), 0);
    }

    fn with_attach(mut p: ProgRecord, a: &str) -> ProgRecord {
        p.attach[..a.len()].copy_from_slice(a.as_bytes());
        p.attach_read = 1;
        p
    }

    fn en(progs: Vec<ProgRecord>, links: Option<Vec<LinkRecord>>) -> Enumeration {
        Enumeration { progs, links }
    }

    fn seen(tgid: u32) -> SeenLoad {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"runc");
        SeenLoad {
            tgid,
            uid: 0,
            prog_type: 15,
            _pad: 0,
            comm,
        }
    }

    fn ids(found: &[Finding]) -> Vec<(char, bool, u32)> {
        found
            .iter()
            .map(|f| match f {
                Finding::Baseline(o) => ('B', o.is_link, o.id),
                Finding::Unseen(o) => ('U', o.is_link, o.id),
                Finding::HeldOutlived(o, _) => ('H', o.is_link, o.id),
            })
            .collect()
    }

    /// Lot 304 (named): the programs of the last enumeration, kept with
    /// their type, name, attach function and load time for the known-program
    /// judge; the next enumeration replaces them.
    #[test]
    fn the_last_enumeration_s_programs_are_kept_for_the_known_judge() {
        let own: BTreeSet<u32> = [1].into();
        let mut w = Watch::default();
        let rfs = with_attach(prog(21, 29, "restrict_filesy"), "bpf_lsm_file_open");
        let mon = prog(35, 23, "sysctl_monitor");
        assert_eq!(w.program(21), None, "before any enumeration");
        judge(
            &mut w,
            vec![],
            &en(vec![prog(1, 29, "nn_hook"), rfs, mon], None),
            &own,
        );
        assert_eq!(
            w.program(21),
            Some(crate::known_system_prog::Program {
                prog_type: 29,
                name: "restrict_filesy".into(),
                attach: "bpf_lsm_file_open".into(),
                load_time: 9_000_000_000,
            })
        );
        // an attach function not read: none named, whatever the bytes
        assert_eq!(w.program(35).map(|p| p.attach), Some(String::new()));
        let mut unread = with_attach(prog(36, 23, "x"), "bpf_lsm_file_open");
        unread.attach_read = 0;
        assert_eq!(program_of(&unread).attach, "");
        assert_eq!(program_of(&with_attach(prog(36, 23, "x"), "f")).attach, "f");
        // the agent's own are enumerated too (the root judge asks by id)
        assert!(w.program(1).is_some());
        // the round proves no program known (the kernel-state round does):
        // its baseline objects carry no loader
        let (f, _) = judge(
            &mut w,
            vec![],
            &en(vec![prog(1, 29, "nn_hook"), rfs, mon], None),
            &own,
        );
        assert_eq!(f.len(), 2);
        assert!(
            f.iter()
                .all(|f| matches!(f, Finding::Baseline(o) if o.known.is_none())),
            "{f:?}"
        );
        // the next enumeration replaces it: a program gone is gone
        judge(&mut w, vec![], &en(vec![mon], None), &own);
        assert_eq!(w.program(21), None);
        assert_eq!(w.program(35).map(|p| p.name), Some("sysctl_monitor".into()));
    }

    /// Lot 290 (named): what was there at the start is the baseline,
    /// signed once after a second enumeration; the agent's own programs and
    /// a program the hook saw loading are never findings; a program that
    /// appears later unseen is signed unseen once, a round after it first
    /// shows; one gone before its second enumeration is not signed.
    #[test]
    fn the_start_is_the_baseline_and_a_later_unseen_program_is_signed_once() {
        let own: BTreeSet<u32> = [1, 2].into();
        let mut w = Watch::default();
        let sd = prog(10, 15, "sd_devices");
        let rk_at_start = prog(11, 2, "kp_at_start");
        let ours = prog(1, 29, "nn_hook");
        let r0 = en(vec![ours, sd, rk_at_start], None);
        assert!(
            judge(&mut w, vec![], &r0, &own).0.is_empty(),
            "first sight: nothing yet"
        );
        let (f, foreign) = judge(&mut w, vec![], &r0, &own);
        assert_eq!(ids(&f), vec![('B', false, 10), ('B', false, 11)]);
        assert_eq!(foreign.len(), 2, "ours is not foreign");
        assert!(judge(&mut w, vec![], &r0, &own).0.is_empty(), "signed once");
        // a container's program the hook saw: never a finding
        let seen_one = prog(20, 15, "runc_dev");
        let r = en(vec![ours, sd, rk_at_start, seen_one], None);
        assert!(judge(&mut w, vec![(20, seen(4242))], &r, &own).0.is_empty());
        assert!(
            judge(&mut w, vec![], &r, &own).0.is_empty(),
            "seen stays seen"
        );
        assert_eq!(w.seen()[&20].tgid, 4242);
        // an unseen one: signed a round after it shows, once
        let hidden = with_attach(prog(30, 29, "hide"), "bpf_lsm_file_open");
        let r = en(vec![ours, sd, rk_at_start, seen_one, hidden], None);
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty());
        let (f, _) = judge(&mut w, vec![], &r, &own);
        assert_eq!(ids(&f), vec![('U', false, 30)]);
        match &f[0] {
            Finding::Unseen(o) => {
                assert_eq!(
                    (o.object_type, o.name.as_str(), o.attach.as_str()),
                    (29, "hide", "bpf_lsm_file_open")
                );
                assert_eq!(o.tag, 0xab00_0000_0000_001e);
            }
            other => panic!("{other:?}"),
        }
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty(), "once");
        // a short-lived one: gone before its second enumeration
        let blip = prog(40, 2, "blip");
        let r = en(vec![ours, sd, blip], None);
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty());
        let r = en(vec![ours, sd], None);
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty());
        // its seen record arriving between the two reads clears it
        let late = prog(50, 26, "late");
        let r = en(vec![ours, late], None);
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty());
        assert!(judge(&mut w, vec![(50, seen(9))], &r, &own).0.is_empty());
    }

    /// Lot 290 (named): a program of the agent's prior run whose release is
    /// pending at the first enumeration and gone at the second is no
    /// baseline; a link is judged through its program — one whose program
    /// the program enumeration does not show is signed itself, a detached
    /// one never; the attach point comes from the function, else the
    /// links' types, else the expected attach type.
    #[test]
    fn a_releasing_program_is_no_baseline_and_a_link_is_judged_through_its_program() {
        let own: BTreeSet<u32> = [1].into();
        let mut w = Watch::default();
        let old_run = prog(5, 29, "bpf_map_guard");
        assert!(
            judge(&mut w, vec![], &en(vec![old_run], Some(vec![])), &own)
                .0
                .is_empty()
        );
        assert!(judge(&mut w, vec![], &en(vec![], Some(vec![])), &own)
            .0
            .is_empty());
        let kp = prog(60, 2, "kp");
        let links = vec![
            LinkRecord {
                id: 7,
                link_type: 7,
                prog_id: 60,
                _pad: 0,
            },
            LinkRecord {
                id: 8,
                link_type: 2,
                prog_id: 99,
                _pad: 0,
            },
            LinkRecord {
                id: 9,
                link_type: 3,
                prog_id: 0,
                _pad: 0,
            },
            LinkRecord {
                id: 10,
                link_type: 2,
                prog_id: 1,
                _pad: 0,
            },
        ];
        let r = en(vec![kp], Some(links));
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty());
        let (f, foreign) = judge(&mut w, vec![], &r, &own);
        assert_eq!(ids(&f), vec![('U', false, 60), ('U', true, 8)]);
        assert_eq!(
            foreign.iter().find(|o| o.id == 60).unwrap().attach,
            "perf_event"
        );
        let l = foreign.iter().find(|o| o.is_link).unwrap();
        assert_eq!(
            (l.id, l.object_type, l.attach.as_str()),
            (8, 2, "program 99 not enumerated")
        );
        let plain = prog(70, 15, "dev");
        assert_eq!(attach_of(&plain, &BTreeMap::new()), "cgroup_device");
        let f = with_attach(prog(71, 26, "fe"), "do_unlinkat");
        assert_eq!(attach_of(&f, &BTreeMap::new()), "do_unlinkat");
    }

    /// Lot 290: the status file names each foreign object, its state and
    /// the loader the hook saw, and every load seen since the start.
    #[test]
    fn the_status_file_names_each_foreign_object_and_its_loader() {
        let own: BTreeSet<u32> = BTreeSet::new();
        let mut w = Watch::default();
        let r = en(
            vec![prog(10, 15, "sd_devices"), prog(20, 15, "runc_dev")],
            None,
        );
        judge(&mut w, vec![(20, seen(77))], &r, &own);
        let (_, foreign) = judge(&mut w, vec![], &r, &own);
        let body = render_status(&w, &foreign);
        assert!(
            body.contains(
                "prog 10 cgroup_device sd_devices ab0000000000000a cgroup_device baseline\n"
            ),
            "{body}"
        );
        assert!(body.contains("prog 20 cgroup_device runc_dev ab00000000000014 cgroup_device seen pid=77 uid=0 comm=runc\n"), "{body}");
        assert!(
            body.contains("load 20 cgroup_device pid=77 uid=0 comm=runc\n"),
            "{body}"
        );
        assert_eq!(
            status_path(Path::new("/run/northnarrow/agent.pid")),
            Path::new("/run/northnarrow/bpf-foreign")
        );
    }

    /// Lot 290 (named; the lab's first round): a program the kernel loaded
    /// before user space started (HID-BPF's `hid_tail_call`, prog id 2 on
    /// the 6.8 guest) is told by its load time — the baseline's object
    /// carries it, the status file says `kernel`; a program loaded later is
    /// not; a load time not read is not; a cgroup program with no attach
    /// type and no link is not named an attach point it may not have.
    #[test]
    fn the_kernel_s_own_program_is_told_by_its_load_time() {
        let own: BTreeSet<u32> = BTreeSet::new();
        let mut w = Watch {
            user_space_since: Some(3_000_000_000),
            ..Watch::default()
        };
        let mut boot = with_attach(prog(2, 26, "built_in"), "some_fn");
        boot.load_time = 1_200_000_000;
        // the 6.8 guest's: loaded by udev's modprobe in the initramfs, after
        // PID 1 started — told by its name and attach function
        let hid = with_attach(prog(6, 26, "hid_tail_call"), "__hid_bpf_tail_call");
        let fake = with_attach(prog(7, 26, "hid_tail_call"), "bpf_lsm_file_open");
        let mut unread = prog(4, 26, "x");
        unread.load_time = 0;
        let mut legacy = prog(5, 15, "sd_devices");
        legacy.expected_attach_type = 0;
        let r = en(
            vec![boot, prog(3, 2, "late"), unread, legacy, hid, fake],
            None,
        );
        judge(&mut w, vec![], &r, &own);
        let (f, foreign) = judge(&mut w, vec![], &r, &own);
        let early: Vec<(u32, bool)> = f
            .iter()
            .map(|f| match f {
                Finding::Baseline(o) | Finding::Unseen(o) | Finding::HeldOutlived(o, _) => {
                    (o.id, o.early)
                }
            })
            .collect();
        assert_eq!(
            early,
            vec![
                (2, true),
                (3, false),
                (4, false),
                (5, false),
                (6, true),
                (7, false)
            ]
        );
        assert_eq!(
            foreign.iter().find(|o| o.id == 5).unwrap().attach,
            "unknown (no link, no attach type)"
        );
        let body = render_status(&w, &foreign);
        assert!(body.contains("some_fn baseline kernel\n"), "{body}");
        assert!(
            body.contains("__hid_bpf_tail_call baseline kernel\n"),
            "{body}"
        );
        assert!(
            body.contains("bpf_lsm_file_open baseline\n"),
            "the name alone is not the kernel's: {body}"
        );
        assert!(
            body.contains("late ab00000000000003 cgroup_device baseline\n"),
            "{body}"
        );
        // PID 1's start: field 22 after the command's parenthesis
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 5 6 7 8 9 10 11 12 20 0 1 0 345 1 2";
        assert_eq!(user_space_start_ns(stat, 100), Some(3_450_000_000));
        assert_eq!(user_space_start_ns("1 (a) b) S", 100), None);
        assert_eq!(user_space_start_ns(stat, 0), None);
    }

    /// Lot 290: the iterator bytes are read as whole records.
    #[test]
    fn the_iterator_bytes_are_whole_records() {
        let p = prog(3, 2, "x");
        let mut bytes = bytemuck::bytes_of(&p).to_vec();
        bytes.extend_from_slice(bytemuck::bytes_of(&p));
        bytes.extend_from_slice(&[1; 40]);
        let got = records::<ProgRecord>(&bytes);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].id, 3);
        assert_eq!(std::mem::size_of::<LinkCreateAttr>(), 16);
        assert_eq!(std::mem::size_of::<IterCreateAttr>(), 8);
    }
}
