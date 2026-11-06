//! Lot 280a: the guarded sysctls judged on the kernel's copy of the write —
//! the agent's half of `agent-ebpf/src/sysctl_guard.rs` (the verdict is
//! `common::sysctl_judge`'s).
//!
//! * [`attach`] loads the `cgroup/sysctl` program and links it to the ROOT
//!   cgroup of the unified hierarchy (`BPF_LINK_CREATE` with no flag: the
//!   kernel attaches a link `BPF_F_ALLOW_MULTI`, `cgroup_bpf_link_attach`,
//!   so a program a child cgroup attaches — in any mode — runs before ours
//!   and never replaces it; `BPF_F_ALLOW_OVERRIDE` is never asked), checks
//!   what the kernel then reports for the root (`BPF_PROG_QUERY`: the
//!   root's mode multi, our program among its programs, any other one
//!   named), and pins the program and its link in a directory of their own
//!   beside the pin root ([`pin_dir`]) — like the start-in-cgroup tracker's
//!   (lot 277): the judge goes on refusing while no agent runs and through
//!   an upgrade, whose purge takes the pin root; the next start attaches
//!   its own program first and only then removes the prior link (never a
//!   moment without one). `uninstall.sh` removes the directory. Where it
//!   cannot attach (no cgroup v2 mount of the root cgroup, a kernel or a
//!   mode that refuses it), lot 273d's write deny is the judge alone — the
//!   fallback, signed degraded and named in the manifest ([`attach_note`]).
//! * The signed per-sysctl opt-out ([`set_opt_outs`]): the per-rule
//!   policy's `sysctl-allow` lines, written to the kernel (`SYSCTL_OPTOUT`,
//!   bound to the boot's session nonce) only from a policy whose signature
//!   the agent verified; [`opt_out_for`] is the integrity round's view of
//!   them (a value they allow is left, not put back).

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aya::maps::{Array, Map, MapData};
use aya::programs::CgroupSysctl;
use aya::Ebpf;
use common::sysctl_judge::{SysctlOptOut, SYSCTL_OPTOUT_SLOTS};
use parking_lot::RwLock;
use tracing::{info, warn};

/// The program (`agent-ebpf/src/sysctl_guard.rs`).
pub const PROGRAM: &str = "nn_sysctl_guard";
/// The signed opt-out's map (pinned by name in the pin root).
pub const OPTOUT_MAP: &str = "SYSCTL_OPTOUT";
/// `[0]` = 1 once [`attach`] linked the program this boot (per boot).
pub const JUDGE_MAP: &str = "SYSCTL_KERNEL_JUDGE";
/// The pin directory's name beside the pin root: `<root>-sysctl`.
pub const PIN_DIR_SUFFIX: &str = "-sysctl";

/// The manifest's attach point when the program is linked.
pub const ATTACH: &str = "cgroup/sysctl:root cgroup (link, multi)";

/// `enum bpf_attach_type`'s `BPF_CGROUP_SYSCTL` (uapi; the test checks it
/// against aya-obj's bindings).
pub const BPF_CGROUP_SYSCTL: u32 = 18;
/// `BPF_F_ALLOW_OVERRIDE` / `BPF_F_ALLOW_MULTI` (uapi).
pub const BPF_F_ALLOW_OVERRIDE: u32 = 1;
pub const BPF_F_ALLOW_MULTI: u32 = 2;
/// `BPF_PROG_QUERY` (uapi `enum bpf_cmd`).
const BPF_PROG_QUERY: u32 = 16;

/// The flags of the root's link (`link_create.flags`): none. A cgroup
/// link refuses any (`cgroup_bpf_link_attach`: `-EINVAL`) and is attached
/// `BPF_F_ALLOW_MULTI` by the kernel itself; the legacy `BPF_PROG_ATTACH`,
/// whose flags choose the mode, is not used.
pub const LINK_FLAGS: u32 = 0;

/// The kernel names the default hierarchy's root cgroup inode 1 (its
/// kernfs id): a cgroup v2 mount whose top directory has another inode is
/// a cgroup namespace's view, not the root.
pub const ROOT_CGROUP_INO: u64 = 1;

/// The pin directory of the judge beside `pin_root` (a sibling: the
/// upgrade's purge of the pin root leaves it).
pub fn pin_dir(pin_root: &Path) -> PathBuf {
    let mut name = pin_root.as_os_str().to_os_string();
    name.push(PIN_DIR_SUFFIX);
    PathBuf::from(name)
}

/// The program's and the link's pins in `dir` (`prog_<name>`,
/// `link_<name>`: the link pin is one the BPF guard knows by name).
pub fn pin_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("prog_{PROGRAM}")),
        dir.join(format!("link_{PROGRAM}")),
    )
}

/// Kept across an upgrade (pinned outside the pin root): the
/// own-programs file marks it so, and `install.sh --upgrade` does not
/// wait for it to unload (`uninstall.sh` does).
pub fn is_kept_program(name: &str) -> bool {
    name == PROGRAM
}

/// The mount point of the cgroup v2 hierarchy's root, from a mount table:
/// the first `cgroup2` mount of the hierarchy's top (`root` `/`). `None`
/// without one (a cgroup v1 host).
pub fn cgroup2_root(table: &crate::mountinfo::MountTable) -> Option<PathBuf> {
    table
        .entries
        .iter()
        .find(|m| m.fstype == "cgroup2" && m.root == Path::new("/"))
        .map(|m| m.mount_point.clone())
}

/// What the kernel reports for the root cgroup's `cgroup/sysctl` slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootQuery {
    pub attach_flags: u32,
    pub prog_ids: Vec<u32>,
}

/// The root's report judged: `Ok` the other programs' ids (none, normally)
/// when the mode is multi and `own` is among them; `Err` why not.
pub fn judge_query(q: &RootQuery, own: u32) -> Result<Vec<u32>, String> {
    if q.attach_flags & BPF_F_ALLOW_OVERRIDE != 0 || q.attach_flags & BPF_F_ALLOW_MULTI == 0 {
        return Err(format!(
            "the root cgroup's cgroup/sysctl mode is {:#x}, not BPF_F_ALLOW_MULTI: a child's \
             program could replace ours",
            q.attach_flags
        ));
    }
    if !q.prog_ids.contains(&own) {
        return Err(format!(
            "our program (id {own}) is not among the root cgroup's ({:?})",
            q.prog_ids
        ));
    }
    Ok(q.prog_ids.iter().copied().filter(|id| *id != own).collect())
}

/// The judge as this boot has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judge {
    /// Linked to the root cgroup; the ids of other `cgroup/sysctl`
    /// programs found there (attached after ours, they run after it).
    Attached { others: Vec<u32> },
    /// Not attached, why: the write deny judges alone.
    Fallback(String),
}

static JUDGE: OnceLock<Judge> = OnceLock::new();
/// The link this boot made, held open: the BPF guard registers the link
/// it finds among the agent's descriptors as its own (a foreign handle,
/// detach or update of it refused) and its self-check expects it.
static LINK: OnceLock<OwnedFd> = OnceLock::new();

/// The boot's judge, once [`attach`]ed.
pub fn judge() -> Option<&'static Judge> {
    JUDGE.get()
}

/// What the fallback costs (the manifest's note, the signed degradation).
pub const FALLBACK_EFFECT: &str =
    "the guarded sysctls are judged by the write deny alone, on the bytes it reads from the \
     writer before the kernel copies them: a second thread of the writer can change them in \
     between (the integrity round puts a harmful value back within 5 s, signed)";

/// The manifest's note of the judge: its attach point, or the fallback.
pub fn attach_note() -> (String, crate::boot::manifest::Took) {
    note_of(judge())
}

/// [`attach_note`] of `judge`.
fn note_of(judge: Option<&Judge>) -> (String, crate::boot::manifest::Took) {
    use crate::boot::manifest::Took;
    match judge {
        Some(Judge::Attached { .. }) => (ATTACH.to_string(), Took::Whole),
        Some(Judge::Fallback(why)) => (
            format!("lsm:file_permission (the write deny alone: {why})"),
            Took::Fallback,
        ),
        None => ("not attached".to_string(), Took::Absent),
    }
}

/// `BPF_LINK_CREATE`'s head of `union bpf_attr` (the rest zero).
#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
}

/// `BPF_OBJ_PIN`'s head of `union bpf_attr`.
#[repr(C)]
struct ObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// `BPF_PROG_QUERY`'s head of `union bpf_attr` (5.15's last field is
/// `prog_cnt`; the pad and the rest are zero for later kernels).
#[repr(C)]
struct ProgQueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    pad: u32,
}

fn sys_bpf<T>(cmd: u32, attr: &mut T) -> std::io::Result<i64> {
    // SAFETY: `attr` is a fully initialised `#[repr(C)]` head of `union
    // bpf_attr` and its exact size is passed (the kernel zero-fills the
    // rest); any fd returned is owned by the caller.
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
        Ok(r)
    }
}

/// Link program `prog_fd` to cgroup `cgroup_fd` (`BPF_CGROUP_SYSCTL`,
/// [`LINK_FLAGS`]).
fn link_create(prog_fd: i32, cgroup_fd: i32) -> std::io::Result<OwnedFd> {
    let mut attr = LinkCreateAttr {
        prog_fd: prog_fd as u32,
        target_fd: cgroup_fd as u32,
        attach_type: BPF_CGROUP_SYSCTL,
        flags: LINK_FLAGS,
    };
    let fd = sys_bpf(common::bpf_cmd::BPF_LINK_CREATE, &mut attr)?;
    // SAFETY: a new descriptor the kernel just returned, owned here only.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Pin `fd` at `path`.
fn obj_pin(fd: i32, path: &Path) -> std::io::Result<()> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut attr = ObjPinAttr {
        pathname: c.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    sys_bpf(common::bpf_cmd::BPF_OBJ_PIN, &mut attr).map(drop)
}

/// The root cgroup's `cgroup/sysctl` programs and mode.
fn query_root(cgroup_fd: i32) -> std::io::Result<RootQuery> {
    let mut ids = [0u32; 64];
    let mut attr = ProgQueryAttr {
        target_fd: cgroup_fd as u32,
        attach_type: BPF_CGROUP_SYSCTL,
        query_flags: 0,
        attach_flags: 0,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: ids.len() as u32,
        pad: 0,
    };
    sys_bpf(BPF_PROG_QUERY, &mut attr)?;
    let n = (attr.prog_cnt as usize).min(ids.len());
    Ok(RootQuery {
        attach_flags: attr.attach_flags,
        prog_ids: ids[..n].to_vec(),
    })
}

/// The root cgroup's directory, opened: the cgroup v2 mount of the
/// hierarchy's top (`/proc/self/mountinfo`), checked to be the root
/// ([`ROOT_CGROUP_INO`]).
fn open_root_cgroup() -> Result<std::fs::File, String> {
    use std::os::unix::fs::MetadataExt;
    let table = crate::mountinfo::read(Path::new("/proc/self/mountinfo"))
        .map_err(|e| format!("/proc/self/mountinfo unreadable: {e}"))?;
    let at = cgroup2_root(&table).ok_or_else(|| {
        "no cgroup v2 mount of the hierarchy's root (a cgroup v1 host)".to_string()
    })?;
    let f = std::fs::File::open(&at).map_err(|e| format!("{}: {e}", at.display()))?;
    let ino = f
        .metadata()
        .map_err(|e| format!("{}: {e}", at.display()))?
        .ino();
    if ino != ROOT_CGROUP_INO {
        return Err(format!(
            "{} is not the root cgroup (inode {ino}: a cgroup namespace's view)",
            at.display()
        ));
    }
    Ok(f)
}

/// Remove the judge's pins in `dir` (its link first: the prior program
/// detaches once this boot's runs) and, when `all`, the directory.
fn purge_pins(dir: &Path, all: bool) {
    if std::fs::symlink_metadata(dir).is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
        antitamper_bpf::purge_stale_pin(dir);
        return;
    }
    let (prog, link) = pin_paths(dir);
    antitamper_bpf::purge_stale_pin(&link);
    antitamper_bpf::purge_stale_pin(&prog);
    if all {
        if let Err(e) = std::fs::remove_dir(dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(error = %e, dir = %dir.display(), "sysctl judge: its pin directory NOT removed");
            }
        }
    }
}

/// `dir` usable for the pins: never a symbolic link or anything but a
/// directory, created `0700`.
fn usable_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(why) = antitamper_bpf::pin_root_refusal_at(dir) {
        return Err(why);
    }
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!("{} is not a directory", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display())),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// Load the program and link it to the root cgroup; with a pin root, pin
/// both in [`pin_dir`] after the prior boot's pins there are removed —
/// this boot's link first, so the root is never without a judge. The
/// opt-out slots are cleared (the policy, loaded next, writes its own) and
/// the judge flag set for the write deny. The boot's judge is
/// [`install`]ed; a fallback removes the prior pins (no older program
/// stays linked where this one is not).
pub fn attach(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Judge {
    let judge = match attach_inner(ebpf, pin_root) {
        Ok(others) => {
            if let Err(e) = set_judge_flag(ebpf, 1) {
                warn!(error = %e, "sysctl judge: the judge flag NOT set — the write deny records an opt-out's write too");
            }
            info!(
                others = ?others,
                "sysctl judge: cgroup/sysctl linked to the root cgroup (multi) — the guarded \
                 sysctls are judged on the kernel's copy of the write"
            );
            Judge::Attached { others }
        }
        Err(why) => {
            if let Some(root) = pin_root {
                purge_pins(&pin_dir(root), true);
            }
            warn!(reason = %why, effect = FALLBACK_EFFECT, "sysctl judge: cgroup/sysctl NOT attached");
            Judge::Fallback(why)
        }
    };
    if let Err(e) = clear_slots(ebpf) {
        warn!(error = %e, "sysctl judge: the opt-out slots NOT cleared (an earlier session's are dead)");
    }
    let _ = JUDGE.set(judge.clone());
    judge
}

fn attach_inner(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<Vec<u32>, String> {
    let root = open_root_cgroup()?;
    let dir = pin_root.map(pin_dir);
    if let Some(d) = &dir {
        usable_dir(d)?;
    }
    let prog: &mut CgroupSysctl = ebpf
        .program_mut(PROGRAM)
        .ok_or_else(|| format!("program {PROGRAM} missing from the eBPF object"))?
        .try_into()
        .map_err(|e| format!("{PROGRAM}: {e}"))?;
    prog.load().map_err(|e| format!("{PROGRAM} load: {e:#}"))?;
    let own = prog
        .info()
        .map_err(|e| format!("{PROGRAM} info: {e}"))?
        .id();
    let link = {
        let fd = prog.fd().map_err(|e| format!("{PROGRAM} fd: {e}"))?;
        link_create(fd.as_fd().as_raw_fd(), root.as_raw_fd())
            .map_err(|e| format!("BPF_LINK_CREATE on the root cgroup: {e}"))?
    };
    if let Some(d) = &dir {
        let (prog_pin, link_pin) = pin_paths(d);
        // this boot's link runs: the prior one goes now (its last
        // reference, the pin: it detaches in the unlink)
        purge_pins(d, false);
        prog.pin(&prog_pin)
            .map_err(|e| format!("pinning {PROGRAM} to {}: {e}", prog_pin.display()))?;
        obj_pin(link.as_raw_fd(), &link_pin)
            .map_err(|e| format!("pinning {PROGRAM}'s link to {}: {e}", link_pin.display()))?;
    }
    // what the kernel reports for the root now: multi, ours among them. The
    // prior link removed above goes through the kernel's workqueue
    // (`bpf_link_put` defers its release), so its program can still be
    // listed for a moment — the lab's upgrade round named it "another
    // program": asked again while another one is there, 2 s at most.
    let mut others = Vec::new();
    for _ in 0..QUERY_TRIES {
        let q = query_root(root.as_raw_fd())
            .map_err(|e| format!("BPF_PROG_QUERY of the root cgroup: {e}"))?;
        others = judge_query(&q, own)?;
        if others.is_empty() {
            break;
        }
        std::thread::sleep(QUERY_PAUSE);
    }
    let _ = LINK.set(link);
    Ok(others)
}

/// How often, and how far apart, the root is asked again while another
/// program is listed there (the prior link's deferred release): 2 s.
const QUERY_TRIES: u32 = 40;
const QUERY_PAUSE: std::time::Duration = std::time::Duration::from_millis(50);

/// The judge flag (`SYSCTL_KERNEL_JUDGE[0]`).
fn set_judge_flag(ebpf: &mut Ebpf, v: u32) -> Result<(), String> {
    let map = ebpf
        .map_mut(JUDGE_MAP)
        .ok_or_else(|| format!("map {JUDGE_MAP} missing from the eBPF object"))?;
    let mut a: Array<&mut MapData, u32> = Array::try_from(map).map_err(|e| e.to_string())?;
    a.set(0, v, 0).map_err(|e| e.to_string())
}

/// aya view of [`SysctlOptOut`].
#[repr(transparent)]
#[derive(Clone, Copy)]
struct AyaOptOut(SysctlOptOut);

// SAFETY: `SysctlOptOut` is `#[repr(C)]` over i64, i64, u32, u32 — no
// padding, every bit pattern valid; `AyaOptOut` is `#[repr(transparent)]`.
unsafe impl aya::Pod for AyaOptOut {}

/// Every slot of `map` disarmed, then `list`'s written for `session`.
fn write_slots<M: std::borrow::BorrowMut<MapData>>(
    map: &mut Array<M, AyaOptOut>,
    list: &[OptOut],
    session: u32,
) -> Result<(), String> {
    for (slot, v) in slot_values(list, session).into_iter().enumerate() {
        map.set(slot as u32, AyaOptOut(v), 0)
            .map_err(|e| format!("{OPTOUT_MAP}[{slot}]: {e}"))?;
    }
    Ok(())
}

/// The map's slots for `list` under `session`: one per kind, the others
/// disarmed.
pub fn slot_values(list: &[OptOut], session: u32) -> Vec<SysctlOptOut> {
    let mut out = vec![SysctlOptOut::default(); SYSCTL_OPTOUT_SLOTS as usize];
    for o in list {
        if let Some(s) = out.get_mut(o.kind as usize) {
            *s = SysctlOptOut {
                min: o.min,
                max: o.max,
                session,
                armed: 1,
            };
        }
    }
    out
}

fn clear_slots(ebpf: &mut Ebpf) -> Result<(), String> {
    let map = ebpf
        .map_mut(OPTOUT_MAP)
        .ok_or_else(|| format!("map {OPTOUT_MAP} missing from the eBPF object"))?;
    let mut a: Array<&mut MapData, AyaOptOut> = Array::try_from(map).map_err(|e| e.to_string())?;
    write_slots(&mut a, &[], 0)
}

/// One opt-out in force: a guarded sysctl's kind and the values allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptOut {
    pub kind: u8,
    pub min: i64,
    pub max: i64,
}

/// The opt-outs in force (from a signed policy only).
static OPT_OUTS: RwLock<Vec<OptOut>> = RwLock::new(Vec::new());

/// The range in force for `kind` (the integrity round's view).
pub fn opt_out_for(kind: u8) -> Option<(i64, i64)> {
    OPT_OUTS
        .read()
        .iter()
        .find(|o| o.kind == kind)
        .map(|o| (o.min, o.max))
}

/// What [`set_opt_outs`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// In force: the kernel's slots written (`kernel: false` when they
    /// could not be — the round honours them, the kernel refuses them).
    InForce { count: usize, kernel: bool },
    /// The policy carries opt-outs but no valid signature: none honoured.
    Withheld { count: usize },
}

/// Put `list` in force — only when `signed` (the policy's signature
/// verified for the very text applied: an unsigned policy loaded through
/// `NN_OVERLAY_ALLOW_UNSIGNED` honours none) — and write it to the
/// kernel's slots through the pins under `pin_root` with the boot's
/// session nonce. An unsigned list clears what was in force.
pub fn set_opt_outs(list: Vec<OptOut>, signed: bool, pin_root: Option<&Path>) -> Applied {
    let count = list.len();
    let in_force = if signed { list } else { Vec::new() };
    let kernel = match write_pinned(&in_force, pin_root) {
        Ok(()) => true,
        Err(e) => {
            if !in_force.is_empty() {
                warn!(error = %e, "sysctl opt-out: NOT written to the kernel — its writes stay refused");
            }
            false
        }
    };
    *OPT_OUTS.write() = in_force;
    if signed {
        Applied::InForce { count, kernel }
    } else {
        Applied::Withheld { count }
    }
}

fn write_pinned(list: &[OptOut], pin_root: Option<&Path>) -> Result<(), String> {
    let root = pin_root.ok_or("no pin root")?;
    let session = {
        let md = MapData::from_pin(root.join("AGENT_SESSION")).map_err(|e| e.to_string())?;
        let a: Array<MapData, u32> = Array::try_from(Map::Array(md)).map_err(|e| e.to_string())?;
        a.get(&0, 0).map_err(|e| e.to_string())?
    };
    let md = MapData::from_pin(root.join(OPTOUT_MAP)).map_err(|e| e.to_string())?;
    let mut a: Array<MapData, AyaOptOut> =
        Array::try_from(Map::Array(md)).map_err(|e| e.to_string())?;
    write_slots(&mut a, list, session)
}

/// The opt-outs in force now.
pub fn opt_outs_now() -> Vec<OptOut> {
    OPT_OUTS.read().clone()
}

/// The `sysctl-allow` lines of `policy` as opt-outs.
pub fn opt_outs_of(policy: &nn_core::decision::rule_policy::RulePolicy) -> Vec<OptOut> {
    policy
        .sysctl_opt_outs()
        .map(|(_, kind, min, max)| OptOut { kind, min, max })
        .collect()
}

/// `policy`'s opt-outs put in force when `signed` ([`set_opt_outs`], the
/// pin root's slots); the detail of a signed degradation when they are not
/// all in force — withheld from an unsigned policy, or not written to the
/// kernel.
pub fn apply_policy(
    policy: &nn_core::decision::rule_policy::RulePolicy,
    signed: bool,
) -> Option<String> {
    let list = opt_outs_of(policy);
    let applied = set_opt_outs(list, signed, antitamper_bpf::prepare_pin_root());
    applied_detail(&applied, &policy.source)
}

/// What an [`Applied`] costs, if anything: the detail of its degradation.
pub fn applied_detail(applied: &Applied, source: &str) -> Option<String> {
    match applied {
        Applied::Withheld { count } if *count > 0 => Some(format!(
            "{source}: {count} sysctl-allow line(s) NOT honoured — the policy was loaded \
             without a valid signature (NN_OVERLAY_ALLOW_UNSIGNED=1): the guarded sysctls' \
             harmful writes stay refused"
        )),
        Applied::InForce {
            count,
            kernel: false,
        } if *count > 0 => Some(format!(
            "{source}: {count} sysctl-allow line(s) in force for the integrity round but NOT \
             written to the kernel (no pin root or session): their writes stay refused"
        )),
        Applied::InForce { count, .. } if *count > 0 => {
            info!(
                count,
                "sysctl opt-out: the signed policy's sysctl-allow lines in force"
            );
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::cgroup_limits::{SYSCTL_PID_MAX, SYSCTL_SCHED_RT_RUNTIME};

    /// The uapi numbers this module writes by hand, against aya-obj's
    /// bindings of the kernel's headers.
    #[test]
    fn the_uapi_numbers_are_the_kernels() {
        use aya_obj::generated::{
            bpf_attach_type, bpf_cmd, BPF_F_ALLOW_MULTI as M, BPF_F_ALLOW_OVERRIDE as O,
        };
        assert_eq!(BPF_CGROUP_SYSCTL, bpf_attach_type::BPF_CGROUP_SYSCTL as u32);
        assert_eq!(BPF_PROG_QUERY, bpf_cmd::BPF_PROG_QUERY as u32);
        assert_eq!(
            common::bpf_cmd::BPF_LINK_CREATE,
            bpf_cmd::BPF_LINK_CREATE as u32
        );
        assert_eq!(common::bpf_cmd::BPF_OBJ_PIN, bpf_cmd::BPF_OBJ_PIN as u32);
        assert_eq!(BPF_F_ALLOW_MULTI, M);
        assert_eq!(BPF_F_ALLOW_OVERRIDE, O);
        assert_eq!(std::mem::size_of::<LinkCreateAttr>(), 16);
        assert_eq!(std::mem::size_of::<ObjPinAttr>(), 16);
        assert_eq!(std::mem::size_of::<ProgQueryAttr>(), 32);
    }

    /// Named test (lot 280a): a program attached to a child cgroup cannot
    /// override the root's judge. Ours is a link with no flag — the kernel
    /// attaches a cgroup link `BPF_F_ALLOW_MULTI`, the one mode in which
    /// the root's programs stay in every descendant's effective array —
    /// never `BPF_F_ALLOW_OVERRIDE`; and the start refuses a root whose
    /// reported mode is not multi, or that does not run our program.
    #[test]
    fn a_child_cgroup_program_cannot_override() {
        assert_eq!(LINK_FLAGS, 0);
        assert_eq!(LINK_FLAGS & BPF_F_ALLOW_OVERRIDE, 0);
        let q = |flags, ids: &[u32]| RootQuery {
            attach_flags: flags,
            prog_ids: ids.to_vec(),
        };
        assert_eq!(judge_query(&q(BPF_F_ALLOW_MULTI, &[7]), 7), Ok(vec![]));
        assert_eq!(
            judge_query(&q(BPF_F_ALLOW_MULTI, &[3, 7, 9]), 7),
            Ok(vec![3, 9])
        );
        for flags in [
            0,
            BPF_F_ALLOW_OVERRIDE,
            BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI,
        ] {
            let e = judge_query(&q(flags, &[7]), 7).unwrap_err();
            assert!(e.contains("not BPF_F_ALLOW_MULTI"), "{flags}: {e}");
        }
        let e = judge_query(&q(BPF_F_ALLOW_MULTI, &[3]), 7).unwrap_err();
        assert!(e.contains("not among"), "{e}");
    }

    /// The pins beside the root, kept across an upgrade by name.
    #[test]
    fn the_pins_live_beside_the_pin_root() {
        let d = pin_dir(Path::new("/sys/fs/bpf/northnarrow"));
        assert_eq!(d, Path::new("/sys/fs/bpf/northnarrow-sysctl"));
        assert!(!d.starts_with("/sys/fs/bpf/northnarrow/"));
        let (p, l) = pin_paths(&d);
        assert_eq!(
            p,
            Path::new("/sys/fs/bpf/northnarrow-sysctl/prog_nn_sysctl_guard")
        );
        assert_eq!(
            l,
            Path::new("/sys/fs/bpf/northnarrow-sysctl/link_nn_sysctl_guard")
        );
        // the BPF guard reads 32 bytes of a pin's last component
        assert!(l.file_name().unwrap().len() < 32);
        assert!(is_kept_program(PROGRAM));
        assert!(!is_kept_program("nn_sysctl"));
        assert!(!is_kept_program("cgroup_join_mark"));
    }

    /// The root of the unified hierarchy: its `cgroup2` mount at the top,
    /// never a sub-tree's mount (a container's view) nor a v1 one.
    #[test]
    fn the_root_cgroup_is_the_cgroup2_mount_of_the_top() {
        let t = |s: &str| crate::mountinfo::parse(s.as_bytes());
        let hybrid = "22 1 0:20 / /sys/fs/cgroup ro,nosuid shared:7 - tmpfs tmpfs ro\n\
            25 22 0:23 / /sys/fs/cgroup/unified rw shared:8 - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_root(&t(hybrid)),
            Some(PathBuf::from("/sys/fs/cgroup/unified"))
        );
        let unified = "35 24 0:30 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_root(&t(unified)),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
        let sub = "35 24 0:30 /system.slice /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        assert_eq!(cgroup2_root(&t(sub)), None);
        let v1 = "30 22 0:25 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        assert_eq!(cgroup2_root(&t(v1)), None);
        assert_eq!(ROOT_CGROUP_INO, 1);
    }

    /// The opt-out's slots: one per kind, armed for the session, the rest
    /// disarmed (an earlier list's slot goes).
    #[test]
    fn the_opt_out_slots_are_the_lists() {
        let list = [
            OptOut {
                kind: SYSCTL_SCHED_RT_RUNTIME,
                min: -1,
                max: -1,
            },
            OptOut {
                kind: SYSCTL_PID_MAX,
                min: 4096,
                max: 32767,
            },
        ];
        let s = slot_values(&list, 0xabc);
        assert_eq!(s.len(), SYSCTL_OPTOUT_SLOTS as usize);
        assert_eq!(
            s[SYSCTL_SCHED_RT_RUNTIME as usize].live(0xabc),
            Some((-1, -1))
        );
        assert_eq!(s[SYSCTL_PID_MAX as usize].live(0xabc), Some((4096, 32767)));
        assert_eq!(s[SYSCTL_PID_MAX as usize].live(0xabd), None);
        let armed = s.iter().filter(|v| v.armed != 0).count();
        assert_eq!(armed, 2);
        assert!(slot_values(&[], 1).iter().all(|v| v.armed == 0));
    }

    /// Named test (lot 280a): the opt-out is honoured only from a policy
    /// whose signature was verified — with one, in force (the round leaves
    /// its range); without, none (and what was in force goes).
    #[test]
    fn the_opt_out_is_honoured_only_signed() {
        let _g = OPT_LOCK.lock();
        let rt = vec![OptOut {
            kind: SYSCTL_SCHED_RT_RUNTIME,
            min: -1,
            max: -1,
        }];
        assert_eq!(
            set_opt_outs(rt.clone(), true, None),
            Applied::InForce {
                count: 1,
                kernel: false
            }
        );
        assert_eq!(opt_out_for(SYSCTL_SCHED_RT_RUNTIME), Some((-1, -1)));
        assert_eq!(opt_out_for(SYSCTL_PID_MAX), None);
        assert_eq!(
            set_opt_outs(rt, false, None),
            Applied::Withheld { count: 1 }
        );
        assert_eq!(opt_out_for(SYSCTL_SCHED_RT_RUNTIME), None);
        assert!(opt_outs_now().is_empty());
    }

    /// A policy's lines become opt-outs; what is not in force is said.
    #[test]
    fn a_policy_s_opt_outs_and_what_is_not_in_force() {
        let p = nn_core::decision::rule_policy::parse(
            "sysctl-allow kernel.sched_rt_runtime_us -1\nenforce R020\n",
        )
        .unwrap();
        assert_eq!(
            opt_outs_of(&p),
            [OptOut {
                kind: SYSCTL_SCHED_RT_RUNTIME,
                min: -1,
                max: -1
            }]
        );
        let w = applied_detail(&Applied::Withheld { count: 1 }, "rule-policy.local").unwrap();
        assert!(w.contains("NOT honoured"), "{w}");
        assert!(w.contains("without a valid signature"), "{w}");
        let k = applied_detail(
            &Applied::InForce {
                count: 2,
                kernel: false,
            },
            "x",
        )
        .unwrap();
        assert!(k.contains("NOT written to the kernel"), "{k}");
        assert_eq!(
            applied_detail(
                &Applied::InForce {
                    count: 2,
                    kernel: true
                },
                "x"
            ),
            None
        );
        assert_eq!(applied_detail(&Applied::Withheld { count: 0 }, "x"), None);
        assert_eq!(
            applied_detail(
                &Applied::InForce {
                    count: 0,
                    kernel: false
                },
                "x"
            ),
            None
        );
    }

    /// The manifest's note: the judge's attach point whole, the write deny
    /// as the fallback with why, nothing before the attach.
    #[test]
    fn the_manifest_names_the_judge_that_runs() {
        use crate::boot::manifest::Took;
        assert_eq!(
            note_of(Some(&Judge::Attached { others: vec![] })),
            (ATTACH.to_string(), Took::Whole)
        );
        let (n, t) = note_of(Some(&Judge::Fallback("no cgroup v2 mount".into())));
        assert_eq!(t, Took::Fallback);
        assert!(n.starts_with("lsm:file_permission"), "{n}");
        assert!(n.contains("no cgroup v2 mount"), "{n}");
        assert_eq!(note_of(None), ("not attached".to_string(), Took::Absent));
    }

    /// The tests that set the process-wide opt-outs, one at a time.
    pub(crate) static OPT_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
}
