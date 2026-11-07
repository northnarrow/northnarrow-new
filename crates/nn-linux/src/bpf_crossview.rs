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
pub const ITER_PROGS: &str = "nn_iter_progs";
/// The link iterator's program (kernels with `bpf_iter_bpf_link`).
pub const ITER_LINKS: &str = "nn_iter_links";
/// The map of the programs the hook saw loading.
pub const SEEN_MAP: &str = "SEEN_PROGS";
/// The status file's name, beside the agent's pid file.
pub const STATUS_FILE_NAME: &str = "bpf-foreign";
/// The signed degradation's source while the cross-view does not run.
pub const DEGRADATION: &str = "bpf_crossview";

/// aya view of [`SeenLoad`].
#[repr(transparent)]
#[derive(Clone, Copy)]
struct AyaSeen(SeenLoad);

// SAFETY: `SeenLoad` is `#[repr(C)]` over u32, u32, [u8; 16] — no padding,
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
        Ok(Parts { progs, links, seen })
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
    /// its links, else its expected attach type.
    pub attach: String,
}

/// A finding to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Present at the start, never seen loading: signed once.
    Baseline(Object),
    /// Appeared later, never seen loading.
    Unseen(Object),
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
        _ => attach_type_name(p.expected_attach_type),
    }
}

impl Watch {
    /// The programs seen loading so far, with their loaders.
    pub fn seen(&self) -> &BTreeMap<u32, SeenLoad> {
        &self.seen
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
    for (key, o) in &candidates {
        if w.signed.contains(key) {
            continue;
        }
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
            "{kind} {} {t} {} {:016x} {} {state}{loader}\n",
            o.id,
            if o.name.is_empty() { "-" } else { &o.name },
            o.tag,
            o.attach.replace(' ', "_"),
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
}

impl CrossView {
    /// One round: the findings to sign. An error stops nothing: the round
    /// says it (a signed degradation while it holds).
    pub fn round(&mut self) -> Result<Vec<Finding>, String> {
        let seen = self.parts.seen()?;
        let en = self.parts.enumerate()?;
        let own = (self.own)();
        let (found, foreign) = judge(&mut self.watch, seen, &en, &own);
        if let Some(path) = &self.status {
            let body = render_status(&self.watch, &foreign);
            if let Err(e) = crate::atomic_file::replace(path, body.as_bytes(), 0o600) {
                tracing::debug!(error = %e, path = %path.display(), "BPF cross-view: status file not written");
            }
        }
        Ok(found)
    }
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
            tag: [0xab, 0, 0, 0, 0, 0, 0, id as u8],
            name: n,
            attach: [0u8; 64],
        }
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
        SeenLoad { tgid, uid: 0, comm }
    }

    fn ids(found: &[Finding]) -> Vec<(char, bool, u32)> {
        found
            .iter()
            .map(|f| match f {
                Finding::Baseline(o) => ('B', o.is_link, o.id),
                Finding::Unseen(o) => ('U', o.is_link, o.id),
            })
            .collect()
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
        assert!(judge(&mut w, vec![], &r0, &own).0.is_empty(), "first sight: nothing yet");
        let (f, foreign) = judge(&mut w, vec![], &r0, &own);
        assert_eq!(ids(&f), vec![('B', false, 10), ('B', false, 11)]);
        assert_eq!(foreign.len(), 2, "ours is not foreign");
        assert!(judge(&mut w, vec![], &r0, &own).0.is_empty(), "signed once");
        // a container's program the hook saw: never a finding
        let seen_one = prog(20, 15, "runc_dev");
        let r = en(vec![ours, sd, rk_at_start, seen_one], None);
        assert!(judge(&mut w, vec![(20, seen(4242))], &r, &own).0.is_empty());
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty(), "seen stays seen");
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
        assert!(judge(&mut w, vec![], &en(vec![old_run], Some(vec![])), &own).0.is_empty());
        assert!(judge(&mut w, vec![], &en(vec![], Some(vec![])), &own).0.is_empty());
        let kp = prog(60, 2, "kp");
        let links = vec![
            LinkRecord { id: 7, link_type: 7, prog_id: 60, _pad: 0 },
            LinkRecord { id: 8, link_type: 2, prog_id: 99, _pad: 0 },
            LinkRecord { id: 9, link_type: 3, prog_id: 0, _pad: 0 },
            LinkRecord { id: 10, link_type: 2, prog_id: 1, _pad: 0 },
        ];
        let r = en(vec![kp], Some(links));
        assert!(judge(&mut w, vec![], &r, &own).0.is_empty());
        let (f, foreign) = judge(&mut w, vec![], &r, &own);
        assert_eq!(ids(&f), vec![('U', false, 60), ('U', true, 8)]);
        assert_eq!(foreign.iter().find(|o| o.id == 60).unwrap().attach, "perf_event");
        let l = foreign.iter().find(|o| o.is_link).unwrap();
        assert_eq!((l.id, l.object_type, l.attach.as_str()), (8, 2, "program 99 not enumerated"));
        let plain = prog(70, 15, "dev");
        assert_eq!(attach_of(&plain, &BTreeMap::new()), "cgroup_device");
        let f = with_attach(prog(71, 26, "fe"), "do_unlinkat");
        assert_eq!(attach_of(&f, &BTreeMap::new()), "do_unlinkat");
    }

    /// Lot 290: the status file names each foreign object, its state and
    /// the loader the hook saw.
    #[test]
    fn the_status_file_names_each_foreign_object_and_its_loader() {
        let own: BTreeSet<u32> = BTreeSet::new();
        let mut w = Watch::default();
        let r = en(vec![prog(10, 15, "sd_devices"), prog(20, 15, "runc_dev")], None);
        judge(&mut w, vec![(20, seen(77))], &r, &own);
        let (_, foreign) = judge(&mut w, vec![], &r, &own);
        let body = render_status(&w, &foreign);
        assert!(body.contains("prog 10 cgroup_device sd_devices ab0000000000000a cgroup_device baseline\n"), "{body}");
        assert!(body.contains("prog 20 cgroup_device runc_dev ab00000000000014 cgroup_device seen pid=77 uid=0 comm=runc\n"), "{body}");
        assert_eq!(
            status_path(Path::new("/run/northnarrow/agent.pid")),
            Path::new("/run/northnarrow/bpf-foreign")
        );
    }

    /// Lot 290: the iterators' bytes are read as whole records.
    #[test]
    fn the_iterator_bytes_are_whole_records() {
        let p = prog(3, 2, "x");
        let mut bytes = bytemuck::bytes_of(&p).to_vec();
        bytes.extend_from_slice(bytemuck::bytes_of(&p));
        bytes.extend_from_slice(&[1, 2, 3]);
        let got = records::<ProgRecord>(&bytes);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].id, 3);
        assert_eq!(std::mem::size_of::<LinkCreateAttr>(), 16);
        assert_eq!(std::mem::size_of::<IterCreateAttr>(), 8);
    }
}
