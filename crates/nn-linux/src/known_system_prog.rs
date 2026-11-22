//! Lot 304: a known system program (`common::bpf_prog_class::
//! KNOWN_SYSTEM_PROGRAMS`), told from any other by its loader — never by
//! its name alone.
//!
//! Two programs a systemd host loads at boot, before the agent starts, were
//! signed as foreign at every start (Debian 13, Ubuntu 26.04, measured):
//! systemd-networkd's `sysctl_monitor` on the root cgroup's `cgroup/sysctl`
//! slot (systemd 257+; NN-L-AT-001 High and a degradation of the sysctl
//! judge), and PID 1's `restrict_filesystems` LSM program (the BPF
//! cross-view's baseline, High: an LSM program's type is refused outside a
//! window). Such a program is a known system program — signed Low, with the
//! proof — only when the kernel says all of this:
//!
//! * the program (the cross-view's enumeration, the kernel's record of it)
//!   has an entry's name, type and attach function;
//! * a process holds a descriptor of the link that attaches THAT program
//!   the entry's way (`/proc/<pid>/fdinfo`, its `prog_id`): a cgroup link
//!   to the ROOT cgroup as `cgroup_sysctl` (`cgroup_id` the root's,
//!   `attach_type` 18), or a tracing link as an LSM program (`attach_type`
//!   27) — the loader keeps it, or the program detaches;
//! * that process runs the entry's packaged executable: `/proc/<pid>/exe`
//!   has the device and the inode of the file at the entry's path, stat'ed
//!   now — a regular file owned by root and writable by no one else (a
//!   copy, a renamed or a replaced binary is none); the process the same
//!   all along (its start read before and after);
//! * it was running when the program was loaded (its start no later than
//!   the program's load time, both on the boot clock);
//! * the program was loaded before the agent started — or the agent's
//!   `bpf` hook saw that very process load it (`SEEN_PROGS`), and then a
//!   root `cgroup/sysctl` attach that followed is one the hook lets through
//!   only inside a trusted-installer window.
//!
//! Anything else — the same name from another loader, a copy of the
//! loader, a program loaded after the start that the hook did not see that
//! process load, a record or a holder that cannot be read — stays what it
//! was (High). The `bpf` hook still refuses a root `cgroup/sysctl` attach
//! and an LSM load outside a window, the known programs' included. What
//! this trusts: the packaged file at the entry's path (a root that replaced
//! it before the agent started is not told apart here), and a loader
//! process no one else steers (a debugger attached to it can make it hold
//! anything).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use common::bpf_prog_class::{
    known_system_program, KnownLink, SeenLoad, ATTACH_LSM_MAC, KNOWN_SYSTEM_PROGRAMS,
};

use crate::posture::lineage::{AsOf, AuthSessionTracker};

/// What the kernel's enumeration says of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub prog_type: u32,
    pub name: String,
    /// Its attach function, when the enumeration read one (an LSM or a
    /// tracing program's).
    pub attach: String,
    /// Boot-clock ns (`bpf_prog_info.load_time`).
    pub load_time: u64,
    /// Lot 386: its tag (`common::bpf_prog_class::tag_word`; 0: not read).
    pub tag: u64,
}

/// A process holding a link of the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    /// Its start, boot-clock ns (`/proc/<pid>/stat`, whole clock ticks).
    pub start_ns: u64,
    /// `(device, inode)` of `/proc/<pid>/exe`.
    pub exe: (u64, u64),
    /// The link it holds.
    pub link_id: u32,
}

/// A known system program, proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub id: u32,
    /// Its entry in `KNOWN_SYSTEM_PROGRAMS`.
    pub entry: usize,
    pub link_id: u32,
    /// The loader.
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    /// Seen loading by the agent's `bpf` hook (else loaded before the
    /// agent's start).
    pub seen: bool,
    /// Lot 386: the program's tag (0: not read) — a re-attach's reference
    /// ([`ReattachReference`]).
    pub tag: u64,
}

/// Program `id`, held by a link of kind `link`: known, or why not. `prog`
/// the enumeration's record of it, `holders` the processes holding such a
/// link of it, `packaged` the `(device, inode)` of a packaged file by its
/// path, `agent_start_ns` the agent's start (boot clock), `seen` its load
/// as the agent's `bpf` hook saw it (`None`: not seen).
pub fn judge(
    id: u32,
    link: KnownLink,
    prog: Option<&Program>,
    holders: &[Holder],
    packaged: &dyn Fn(&str) -> Option<(u64, u64)>,
    agent_start_ns: Option<u64>,
    seen: Option<&SeenLoad>,
) -> Result<Known, String> {
    let p = prog.ok_or("its record is not in the BPF enumeration")?;
    let entry = known_system_program(&p.name, p.prog_type, &p.attach, link).ok_or_else(|| {
        format!(
            "`{}` (type {}, attach `{}`) is no known system program",
            p.name, p.prog_type, p.attach
        )
    })?;
    let known = KNOWN_SYSTEM_PROGRAMS[entry];
    let loader = packaged(known.loader)
        .ok_or_else(|| format!("{} is not there as a packaged file", known.loader))?;
    if holders.is_empty() {
        return Err("no process holds its link".to_string());
    }
    let mut why = Vec::new();
    for h in holders {
        let who = format!("pid {} ({})", h.pid, h.comm);
        if h.exe != loader {
            why.push(format!("{who} does not run {}", known.loader));
            continue;
        }
        if h.start_ns > p.load_time {
            why.push(format!("{who} started after its load"));
            continue;
        }
        let seen_by_it = match seen {
            Some(s) if s.tgid == h.pid => true,
            Some(s) => {
                why.push(format!(
                    "the bpf hook saw pid {} load it, not {who}",
                    s.tgid
                ));
                continue;
            }
            None => false,
        };
        if !seen_by_it && !agent_start_ns.is_some_and(|a| p.load_time < a) {
            why.push(format!(
                "loaded after the agent's start and not seen loading by {who}"
            ));
            continue;
        }
        return Ok(Known {
            id,
            entry,
            link_id: h.link_id,
            pid: h.pid,
            uid: h.uid,
            comm: h.comm.clone(),
            seen: seen_by_it,
            tag: p.tag,
        });
    }
    Err(why.join("; "))
}

/// `(device, inode)` of the packaged file at `path` under `root` (`/`): a
/// regular file owned by `owner` (root) and writable by no one else, links
/// followed.
pub fn packaged(root: &Path, path: &str, owner: u32) -> Option<(u64, u64)> {
    let m = antitamper_bpf::kernel_roots::metadata(root.join(path.trim_start_matches('/'))).ok()?;
    (m.is_file() && m.uid() == owner && m.permissions().mode() & 0o022 == 0)
        .then(|| (m.dev(), m.ino()))
}

/// One `/proc/<pid>/fdinfo/<fd>` of a BPF link, as far as it is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkInfo {
    pub link_type: String,
    pub link_id: u32,
    pub prog_id: u32,
    pub cgroup_id: Option<u64>,
    pub attach_type: Option<u32>,
}

/// The link fields of an fdinfo text (`key:\tvalue` lines).
pub fn parse_link_fdinfo(text: &str) -> LinkInfo {
    let mut l = LinkInfo::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "link_type" => l.link_type = v.to_string(),
            "link_id" => l.link_id = v.parse().unwrap_or(0),
            "prog_id" => l.prog_id = v.parse().unwrap_or(0),
            "cgroup_id" => l.cgroup_id = v.parse().ok(),
            "attach_type" => l.attach_type = v.parse().ok(),
            _ => {}
        }
    }
    l
}

impl LinkInfo {
    /// The link attaches program `id` the way `link` says: to the root
    /// cgroup as `cgroup_sysctl`, or as an LSM program.
    pub fn attaches(&self, id: u32, link: KnownLink) -> bool {
        if id == 0 || self.prog_id != id {
            return false;
        }
        match link {
            KnownLink::RootCgroupSysctl => {
                self.link_type == "cgroup"
                    && self.cgroup_id == Some(crate::sysctl_cgroup::ROOT_CGROUP_INO)
                    && self.attach_type == Some(crate::sysctl_cgroup::BPF_CGROUP_SYSCTL)
            }
            KnownLink::Lsm => {
                self.link_type == "tracing" && self.attach_type == Some(ATTACH_LSM_MAC)
            }
        }
    }
}

/// The link of program `id` (kind `link`) that the process at `pdir`
/// (`/proc/<pid>`) holds, if any: its BPF link descriptors' fdinfo.
fn held_link(pdir: &Path, id: u32, link: KnownLink) -> Option<u32> {
    // lot 353 (the review of #563, F2): beneath the anchored /proc root
    let fds = antitamper_bpf::kernel_roots::read_dir(pdir.join("fd")).ok()?;
    for fd in fds {
        let is_link = antitamper_bpf::kernel_roots::read_link(pdir.join("fd").join(&fd))
            .is_ok_and(|t| t.as_os_str().as_encoded_bytes() == b"anon_inode:bpf_link");
        if !is_link {
            continue;
        }
        let Ok(text) = antitamper_bpf::kernel_roots::read_to_string(pdir.join("fdinfo").join(&fd))
        else {
            continue;
        };
        let l = parse_link_fdinfo(&text);
        if l.attaches(id, link) {
            return Some(l.link_id);
        }
    }
    None
}

/// The start of the process at `pdir`, boot-clock ns.
fn start_ns(pdir: &Path, clk_tck: u64) -> Option<u64> {
    start_ns_by(pdir, clk_tck, &|p| crate::state_read::read_state(p).ok())
}

/// [`start_ns`], its `stat` read by `read`.
fn start_ns_by(pdir: &Path, clk_tck: u64, read: &dyn Fn(&Path) -> Option<String>) -> Option<u64> {
    let stat = read(&pdir.join("stat"))?;
    crate::bpf_crossview::user_space_start_ns(&stat, clk_tck)
}

/// The real uid of the process at `pdir` (`status`' `Uid:` line).
fn real_uid(pdir: &Path) -> Option<u32> {
    let status = crate::state_read::read_state(pdir.join("status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Every process under `proc` (`/proc`) holding a link of program `id` of
/// kind `link`, read as one process throughout (its start the same before
/// and after; one that cannot be read is left out).
pub fn holders(proc: &Path, id: u32, link: KnownLink, clk_tck: u64) -> Vec<Holder> {
    // lot 311 (N6): a holder's `stat` read as bytes — its `comm` is its own
    holders_by(proc, id, link, clk_tck, &|p| {
        crate::state_read::read_state(p).ok()
    })
}

/// [`holders`], each `stat` read by `read_stat`.
fn holders_by(
    proc: &Path,
    id: u32,
    link: KnownLink,
    clk_tck: u64,
    read_stat: &dyn Fn(&Path) -> Option<String>,
) -> Vec<Holder> {
    // lot 353 (the review of #563, F2): beneath the anchored /proc root
    let Ok(dir) = antitamper_bpf::kernel_roots::read_dir(proc) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in dir {
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let pdir = proc.join(&name);
        let Some(start) = start_ns_by(&pdir, clk_tck, read_stat) else {
            continue;
        };
        let Some(link_id) = held_link(&pdir, id, link) else {
            continue;
        };
        let (Ok(exe), Some(uid)) = (
            antitamper_bpf::kernel_roots::metadata(pdir.join("exe")),
            real_uid(&pdir),
        ) else {
            continue;
        };
        let comm = crate::state_read::read_state(pdir.join("comm"))
            .map(|c| c.trim_end().to_string())
            .unwrap_or_default();
        if start_ns_by(&pdir, clk_tck, read_stat) != Some(start) {
            continue;
        }
        out.push(Holder {
            pid,
            uid,
            comm,
            start_ns: start,
            exe: (exe.dev(), exe.ino()),
            link_id,
        });
    }
    out.sort_by_key(|h| h.pid);
    out
}

/// Lot 340 (the alpha's daily false positives): a refused load of
/// `prog_type` by `pid` is a known system program's feature probe
/// ([`common::bpf_prog_class::KNOWN_SYSTEM_PROBES`]) — the entry, or why
/// not. The review of #552 (F5a): the proof is the loader's identity WHEN
/// IT LOADED — `image`, the device and inode its exec recorded (the LSM
/// program's, in the kernel's form, whatever the loader's mount namespace:
/// systemd-networkd runs in its own), as of the load
/// ([`AuthSessionTracker::exec_file`]) — never `/proc/<pid>/exe` read as
/// the record is decoded: a root process that loads, then executes the
/// packaged systemd before the decode, showed systemd's image there.
///
/// * `image` is the device and inode of the entry's packaged loader
///   (`packaged`, on the host [`packaged`]: a regular file owned by root and
///   writable by no one else; a copy, a renamed or a replaced binary is
///   none);
/// * the review of #552 (F5b): an entry for PID 1 (`lsm`, at a
///   `daemon-reexec`) only for PID 1 itself.
///
/// What this trusts: the packaged loader file (a root that replaced it is
/// not told apart) and a loader process no one else steers (a debugger
/// attached to it, or a preload root gave it, can make it load anything —
/// of a type the hook refuses all the same).
pub fn known_probe(
    image: Option<(u64, u64)>,
    packaged: &dyn Fn(&str) -> Option<(u64, u64)>,
    pid: u32,
    prog_type: u32,
) -> Result<usize, String> {
    use common::bpf_prog_class::{known_system_probe, KNOWN_SYSTEM_PROBES};
    let image = image.ok_or_else(|| {
        format!("pid {pid}: no exec of it recorded with its image as of the load")
    })?;
    KNOWN_SYSTEM_PROBES
        .iter()
        .filter(|k| k.prog_type == prog_type)
        .find(|k| {
            packaged(k.loader).map(|(dev, ino)| (common::wire::exe::kernel_dev(dev), ino))
                == Some(image)
        })
        .and_then(|k| known_system_probe(k.loader, prog_type, pid))
        .ok_or_else(|| {
            format!(
                "pid {pid} ran no packaged loader of a known probe of program type {prog_type} \
                 when it loaded"
            )
        })
}

/// [`known_probe`] of a load at `at_ns` (`CLOCK_MONOTONIC`): the loader's
/// image as `lineage`'s exec records give it as of the load, the packaged
/// loaders by `packaged`.
pub fn known_probe_by(
    lineage: &AuthSessionTracker,
    packaged: &dyn Fn(&str) -> Option<(u64, u64)>,
    pid: u32,
    prog_type: u32,
    at_ns: u64,
) -> Result<usize, String> {
    known_probe(
        lineage.exec_file(pid, AsOf::judged(at_ns)),
        packaged,
        pid,
        prog_type,
    )
}

/// [`known_probe_by`] on this host (the packaged loaders under `/`). Called
/// once the bus taught the lineage every exec that reached it before the
/// record (the review of #552, F5a: an exec still on its way is no proof —
/// the record keeps High).
pub fn known_probe_on_host(
    lineage: &AuthSessionTracker,
    pid: u32,
    prog_type: u32,
    at_ns: u64,
) -> Result<usize, String> {
    known_probe_by(
        lineage,
        &|path| packaged(Path::new("/"), path, 0),
        pid,
        prog_type,
        at_ns,
    )
}

/// Lot 373: where the distributions install `bpftool` itself — Debian's
/// `bpftool` package, Ubuntu 26.04's; Ubuntu's `linux-tools` puts it under
/// `/usr/lib/linux-tools-<version>/` ([`is_bpftool_path`]), which its
/// `/usr/sbin/bpftool` (a shell script) executes.
pub const BPFTOOL_PATHS: &[&str] = &["/usr/sbin/bpftool", "/usr/bin/bpftool", "/sbin/bpftool"];

/// Lot 373: `path` is where a package installs `bpftool` ([`BPFTOOL_PATHS`],
/// or `/usr/lib/linux-tools-<version>/bpftool`, `/usr/lib/linux-tools/<version>/bpftool`).
pub fn is_bpftool_path(path: &str) -> bool {
    if BPFTOOL_PATHS.contains(&path) {
        return true;
    }
    let Some(dir) = path.strip_suffix("/bpftool") else {
        return false;
    };
    let version = dir
        .strip_prefix("/usr/lib/linux-tools-")
        .or_else(|| dir.strip_prefix("/usr/lib/linux-tools/"));
    version.is_some_and(|v| {
        !v.is_empty()
            && v.len() <= 64
            && !v.starts_with('.')
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    })
}

/// Lot 373: the command lines of `bpftool` that only list or show objects
/// — `[-j|-p|--json|--pretty…] prog|map [show|list [id <id>]]`, and `cgroup
/// tree` for a program — of the kind `kind` (1 a map, 2 a program) whose
/// handle by id `id` was refused. Every one takes a handle by id on each
/// object it prints only to read its information (`BPF_OBJ_GET_INFO_BY_FD`);
/// a dump, an update, a pin, a detach, a load is none of them.
pub fn bpftool_listing_argvs(kind: u64, id: u64) -> Vec<Vec<String>> {
    const OPTIONS: &[&[&str]] = &[
        &[],
        &["-j"],
        &["-p"],
        &["--json"],
        &["--pretty"],
        &["-j", "-p"],
        &["-p", "-j"],
        &["-jp"],
        &["-pj"],
        &["--json", "--pretty"],
        &["--pretty", "--json"],
    ];
    let object = match kind {
        1 => "map",
        2 => "prog",
        _ => return Vec::new(),
    };
    let id = id.to_string();
    let mut verbs: Vec<Vec<&str>> = vec![
        vec![object],
        vec![object, "show"],
        vec![object, "list"],
        vec![object, "show", "id", &id],
        vec![object, "list", "id", &id],
    ];
    if kind == 2 {
        verbs.push(vec!["cgroup", "tree"]);
    }
    let mut out = Vec::new();
    for opts in OPTIONS {
        for verb in &verbs {
            let mut argv = vec!["bpftool".to_string()];
            argv.extend(opts.iter().map(|s| s.to_string()));
            argv.extend(verb.iter().map(|s| s.to_string()));
            out.push(argv);
        }
    }
    out
}

/// Lot 373 (the rc7 soak: the bench's `sudo bpftool prog show` was NN-L-AT-001
/// High at every boot, ENGAGED): a refused handle by id on one of the
/// agent's maps or programs (`kind` 1 or 2, `id`) is the packaged
/// `bpftool` listing or showing objects — `Ok(its path)` when every fact
/// holds, each from the taker's exec as of the refusal:
///
/// * the file it executed (`exe`, `image`: the LSM program's device and
///   inode) is the host's file at a [`is_bpftool_path`], as `packaged`
///   reads it (a regular file owned by root and writable by no one else);
///   a copy, a program of its own (python's ctypes), another mount
///   namespace's file is not;
/// * it executed it as root (`uid`);
/// * its command line, read whole, is one of [`bpftool_listing_argvs`]
///   (`argv_is`, the lineage's digest of it): a dump, an update, a pin, a
///   detach is none.
///
/// Refused all the same; NN-L-AT-001 records it Low and the posture raises
/// nothing. What this trusts: the packaged tool, and a listing being one
/// (another refused operation of the same process is judged on its own).
pub fn bpftool_listing(
    exe: Option<&str>,
    image: Option<(u64, u64)>,
    uid: Option<u32>,
    argv_is: &dyn Fn(&[&str]) -> bool,
    packaged: &dyn Fn(&str) -> Option<(u64, u64)>,
    (kind, id): (u64, u64),
) -> Result<String, String> {
    let exe = exe.ok_or("no exec of it recorded as of the refusal")?;
    if !is_bpftool_path(exe) {
        return Err(format!("{exe} is not where a package installs bpftool"));
    }
    let image = image.ok_or("no image of its exec recorded")?;
    let file = packaged(exe).map(|(dev, ino)| (common::wire::exe::kernel_dev(dev), ino));
    if file != Some(image) {
        return Err(format!("it did not run the packaged {exe}"));
    }
    if uid != Some(0) {
        return Err("not run by root".to_string());
    }
    let listed = bpftool_listing_argvs(kind, id).iter().any(|argv| {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        argv_is(&argv)
    });
    if !listed {
        return Err("its command line is no listing (show, list, cgroup tree)".to_string());
    }
    Ok(exe.to_string())
}

/// [`bpftool_listing`] on this host: the taker `pid`'s exec as `lineage`
/// recorded it as of the refusal at `at_ns`, the packaged file under `/`
/// in a directory root's and writable by no one else.
pub fn bpftool_listing_on_host(
    lineage: &AuthSessionTracker,
    pid: u32,
    kind_id: (u64, u64),
    at_ns: u64,
) -> Result<String, String> {
    let as_of = AsOf::judged(at_ns);
    let id = lineage.exec_identity(pid, as_of);
    let exe = id
        .as_ref()
        .filter(|i| !i.interprets())
        .map(|i| i.exe.to_string_lossy().into_owned());
    bpftool_listing(
        exe.as_deref(),
        lineage.exec_file(pid, as_of),
        lineage.exec_uid(pid, as_of),
        &|argv| lineage.exec_argv_is(pid, as_of, argv),
        &packaged_in_root_dir,
        kind_id,
    )
}

/// Lot 386: the packaged file at `path` on this host ([`packaged`] under
/// `/`, owned by root), its directory root's and writable by no one else —
/// `None` otherwise. [`bpftool_listing_on_host`]'s and
/// [`known_reattach_on_host`]'s view of a packaged executable.
fn packaged_in_root_dir(path: &str) -> Option<(u64, u64)> {
    let dir_ok = Path::new(path).parent().is_some_and(|d| {
        antitamper_bpf::kernel_roots::metadata(d)
            .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.permissions().mode() & 0o022 == 0)
    });
    if dir_ok {
        packaged(Path::new("/"), path, 0)
    } else {
        None
    }
}

/// Lot 386: the tags a re-attach of a known root program is proven by
/// ([`known_reattach`]) — each the tag of the program a known system
/// program's packaged loader attached to the root's `cgroup/sysctl` slot
/// BEFORE the agent started, as the kernel-state round proved it (lot 304,
/// [`Known::seen`] false), by its entry. Kept for the agent's life, in
/// memory only: an agent started after the monitor's re-attach was refused
/// has none (the re-attach is High; `KNOWN_LIMITATIONS.md`). At most
/// [`ReattachReference::CAP`] (a boot attaches one).
#[derive(Debug, Default)]
pub struct ReattachReference(std::sync::Mutex<Vec<(usize, u64)>>);

impl ReattachReference {
    /// The tags kept at most.
    pub const CAP: usize = 8;

    /// An empty reference (no program proven yet).
    pub const fn new() -> Self {
        Self(std::sync::Mutex::new(Vec::new()))
    }

    /// Keep `k`'s tag when the round proved it loaded before the agent
    /// started by an entry of the root's slot; a program the hook saw
    /// loading (a window's), an unread tag, an LSM entry, one more past the
    /// cap: nothing kept.
    pub fn note(&self, k: &Known) {
        let root = common::bpf_prog_class::KNOWN_SYSTEM_PROGRAMS
            .get(k.entry)
            .is_some_and(|e| e.link == KnownLink::RootCgroupSysctl);
        if k.seen || k.tag == 0 || !root {
            return;
        }
        let mut tags = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if !tags.contains(&(k.entry, k.tag)) && tags.len() < Self::CAP {
            tags.push((k.entry, k.tag));
        }
    }

    /// The tags kept, with their entries.
    pub fn tags(&self) -> Vec<(usize, u64)> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Lot 386: this agent's [`ReattachReference`] (the kernel-state round
/// notes, the decision thread reads).
pub static REATTACH_REFERENCE: ReattachReference = ReattachReference::new();

/// Lot 386: what the agent knows of a refused root `cgroup/sysctl` attach
/// and of its attacher, as of the attach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReattachFacts {
    /// The attached program's tag as the `bpf` hook read it (0: not read).
    pub tag: u64,
    /// The file the attacher executed (its exec as of the attach; `None`
    /// for an interpreter's script, or no exec recorded).
    pub exe: Option<String>,
    /// That file's device (the kernel's form) and inode, as its exec
    /// recorded it.
    pub image: Option<(u64, u64)>,
    /// The uid it executed it as, and the record's uid (at the attach).
    pub exec_uid: Option<u32>,
    pub uid: u32,
    /// The process that forked it, by the kernel's fork record, when that
    /// exec was the program the fork ran (through a verified
    /// `systemd-executor`).
    pub fork_parent: Option<u32>,
    /// The systemd service whose cgroup places it, read for its start.
    pub unit: Option<String>,
}

/// Lot 386 (the rc12 soak, R18: networkd restarted by an upgrade while the
/// agent ran; its sysctl monitor's re-attach refused and signed High, "an
/// attempt on the sensor itself"): a refused attach of a `cgroup/sysctl`
/// program to the root cgroup is the packaged loader of a known root program
/// re-attaching that program — its entry, or why not. Every fact holds:
///
/// * the program's tag (`f.tag`, read by the hook from the descriptor
///   attached) is one of `references` ([`ReattachReference`]): the same
///   instructions as the program that entry's loader attached before the
///   agent started — another object, a program of the attacher's own, a
///   changed one is not;
/// * the attacher executed the entry's packaged loader (`f.exe`, not an
///   interpreter's script) and its exec's image is that file now
///   (`packaged`: device and inode, a regular file owned by root and
///   writable by no one else, in such a directory) — a copy, another mount
///   namespace's file, one replaced since the exec is not;
/// * it executed it as the entry's account (`account_uid`), and attached as
///   that account;
/// * PID 1 forked it, and that exec was the program the fork ran (the
///   kernel's fork record) — a process another forked, an orphan PID 1
///   adopted, a wrapper's exec before it is not;
/// * the systemd service whose cgroup places it is the entry's unit.
///
/// Refused all the same: NN-L-AT-001 signs it Low and the posture raises
/// nothing. What this trusts: lot 304's proof of the program attached before
/// the agent started, and a program of the same tag doing what that one did
/// (the tag binds its instructions, not its maps: the monitor's
/// instructions never change a sysctl write, whatever maps it is given).
pub fn known_reattach(
    f: &ReattachFacts,
    references: &[(usize, u64)],
    packaged: &dyn Fn(&str) -> Option<(u64, u64)>,
    account_uid: &dyn Fn(&str) -> Option<u32>,
) -> Result<usize, String> {
    use common::bpf_prog_class::KNOWN_SYSTEM_PROGRAMS;
    if f.tag == 0 {
        return Err("the hook read no program from the attach".to_string());
    }
    let entry = references
        .iter()
        .find(|(e, tag)| {
            *tag == f.tag
                && KNOWN_SYSTEM_PROGRAMS
                    .get(*e)
                    .is_some_and(|k| k.link == KnownLink::RootCgroupSysctl)
        })
        .map(|(e, _)| *e)
        .ok_or_else(|| {
            format!(
                "its tag {} is no tag of a known program attached to the root before the agent                  started",
                common::bpf_prog_class::tag_hex(f.tag)
            )
        })?;
    let k = KNOWN_SYSTEM_PROGRAMS[entry];
    if f.exe.as_deref() != Some(k.loader) {
        return Err(format!("it did not execute {}", k.loader));
    }
    let file = packaged(k.loader).map(|(dev, ino)| (common::wire::exe::kernel_dev(dev), ino));
    if f.image.is_none() || f.image != file {
        return Err(format!("it did not run the packaged {}", k.loader));
    }
    let account = account_uid(k.user).ok_or_else(|| format!("no account {}", k.user))?;
    if f.exec_uid != Some(account) || f.uid != account {
        return Err(format!("not run as {}", k.user));
    }
    if f.fork_parent != Some(1) {
        return Err("not the program a fork of PID 1 ran".to_string());
    }
    if f.unit.as_deref() != Some(k.unit) {
        return Err(format!("not in {}'s cgroup", k.unit));
    }
    Ok(entry)
}

/// [`known_reattach`] on this host: [`known_reattach_by`] with the
/// references [`REATTACH_REFERENCE`] kept and the packaged loader under `/`
/// in a directory root's ([`packaged_in_root_dir`]). Called once the bus
/// taught the lineage every exec that reached it before the record.
pub fn known_reattach_on_host(
    lineage: &AuthSessionTracker,
    pid: u32,
    uid: u32,
    tag: u64,
    at_ns: u64,
) -> Result<usize, String> {
    known_reattach_by(
        lineage,
        &REATTACH_REFERENCE.tags(),
        &packaged_in_root_dir,
        (pid, uid),
        tag,
        at_ns,
    )
}

/// [`known_reattach`] of the attacher `pid` (uid `uid` at the attach) of
/// a program of tag `tag` refused at `at_ns` (`CLOCK_MONOTONIC`), as
/// `lineage` recorded it as of the refusal — its exec's file, image, uid and
/// fork record, its service read for the start that exec recorded, the
/// account from the host's `/etc/passwd`.
pub fn known_reattach_by(
    lineage: &AuthSessionTracker,
    references: &[(usize, u64)],
    packaged: &dyn Fn(&str) -> Option<(u64, u64)>,
    (pid, uid): (u32, u32),
    tag: u64,
    at_ns: u64,
) -> Result<usize, String> {
    let as_of = AsOf::judged(at_ns);
    let exe = lineage
        .exec_identity(pid, as_of)
        .filter(|i| !i.interprets())
        .map(|i| i.exe.to_string_lossy().into_owned());
    let start = lineage
        .lineage_starts(pid, as_of)
        .first()
        .filter(|(p, s)| *p == pid && *s != 0)
        .map(|(_, s)| *s);
    let facts = ReattachFacts {
        tag,
        exe,
        image: lineage.exec_file(pid, as_of),
        exec_uid: lineage.exec_uid(pid, as_of),
        uid,
        fork_parent: lineage.fork_parent(pid, as_of),
        unit: start.and_then(|s| lineage.system_service_started(pid, s)),
    };
    known_reattach(&facts, references, packaged, &|name| {
        lineage.account_uid(name)
    })
}

/// The host's clock ticks a second.
pub fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100)
}

/// The agent's own start, boot-clock ns.
pub fn agent_start_ns() -> Option<u64> {
    start_ns(Path::new("/proc/self"), clk_tck())
}

/// Program `id` on this host, held by a link of kind `link`: known, or why
/// not — `prog` its enumeration record, `seen` its load as the `bpf` hook
/// saw it. `/proc` is read only for a program an entry names.
pub fn judge_on_host(
    id: u32,
    link: KnownLink,
    prog: Option<&Program>,
    agent_start_ns: Option<u64>,
    seen: Option<&SeenLoad>,
) -> Result<Known, String> {
    let host = Host {
        proc: Path::new("/proc"),
        root: Path::new("/"),
        owner: 0,
        clk_tck: clk_tck(),
    };
    host.judge(id, link, prog, agent_start_ns, seen)
}

/// Where [`judge_on_host`] reads: `/proc`, the packaged files' root and
/// their owner (`/`, root), the clock ticks.
pub struct Host<'a> {
    pub proc: &'a Path,
    pub root: &'a Path,
    pub owner: u32,
    pub clk_tck: u64,
}

impl Host<'_> {
    /// [`judge_on_host`] on this host.
    pub fn judge(
        &self,
        id: u32,
        link: KnownLink,
        prog: Option<&Program>,
        agent_start_ns: Option<u64>,
        seen: Option<&SeenLoad>,
    ) -> Result<Known, String> {
        let named = prog
            .is_some_and(|p| known_system_program(&p.name, p.prog_type, &p.attach, link).is_some());
        let holders = if named {
            holders(self.proc, id, link, self.clk_tck)
        } else {
            Vec::new()
        };
        judge(
            id,
            link,
            prog,
            &holders,
            &|path| packaged(self.root, path, self.owner),
            agent_start_ns,
            seen,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::bpf_prog_class::{PROG_TYPE_CGROUP_SYSCTL, PROG_TYPE_LSM};

    /// The networkd monitor's tag in these tests (the debian13 guest's link
    /// fdinfo: `prog_tag 342fe7f347490662`).
    const MONITOR_TAG: u64 = 0x342f_e7f3_4749_0662;

    /// Lot 386 (named, the rc12 soak's R18: networkd restarted by an upgrade
    /// while the agent ran, its monitor's re-attach signed High): the
    /// packaged networkd re-attaching the program it attached before the
    /// agent started is proven — every fact at once; each fact alone
    /// missing or wrong (another program, no tag read, no reference, a copy
    /// or a replaced binary, an interpreter, another account at the exec or
    /// at the attach, a process PID 1 did not fork as that program, another
    /// unit's cgroup, an entry with no unit) keeps it High.
    #[test]
    fn a_networkd_monitor_reattach_is_proven_by_its_identity_and_its_tag() {
        const IMG: (u64, u64) = (common::wire::exe::kernel_dev(0x801), 386_001);
        let loader = "/usr/lib/systemd/systemd-networkd";
        let packaged = |p: &str| (p == loader).then_some((0x801, 386_001));
        let accounts = |n: &str| match n {
            "systemd-network" => Some(998),
            "root" => Some(0),
            _ => None,
        };
        let refs = [(1usize, 0x1111), (0usize, MONITOR_TAG)];
        let good = ReattachFacts {
            tag: MONITOR_TAG,
            exe: Some(loader.into()),
            image: Some(IMG),
            exec_uid: Some(998),
            uid: 998,
            fork_parent: Some(1),
            unit: Some("systemd-networkd.service".into()),
        };
        assert_eq!(known_reattach(&good, &refs, &packaged, &accounts), Ok(0));
        type Case<'a> = (&'a str, ReattachFacts, &'a [(usize, u64)]);
        let cases: Vec<Case> = vec![
            (
                "no tag read",
                ReattachFacts {
                    tag: 0,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "another program",
                ReattachFacts {
                    tag: 0x7f3a,
                    ..good.clone()
                },
                &refs,
            ),
            ("no reference (an agent started after)", good.clone(), &[]),
            (
                "the LSM entry's tag",
                ReattachFacts {
                    tag: 0x1111,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "an interpreter",
                ReattachFacts {
                    exe: None,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "a copy",
                ReattachFacts {
                    exe: Some("/tmp/systemd-networkd".into()),
                    ..good.clone()
                },
                &refs,
            ),
            (
                "a replaced binary",
                ReattachFacts {
                    image: Some((IMG.0, 9)),
                    ..good.clone()
                },
                &refs,
            ),
            (
                "no image recorded",
                ReattachFacts {
                    image: None,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "root at the exec",
                ReattachFacts {
                    exec_uid: Some(0),
                    ..good.clone()
                },
                &refs,
            ),
            (
                "no exec uid",
                ReattachFacts {
                    exec_uid: None,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "root at the attach",
                ReattachFacts {
                    uid: 0,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "another forker",
                ReattachFacts {
                    fork_parent: Some(4242),
                    ..good.clone()
                },
                &refs,
            ),
            (
                "no fork record",
                ReattachFacts {
                    fork_parent: None,
                    ..good.clone()
                },
                &refs,
            ),
            (
                "another unit",
                ReattachFacts {
                    unit: Some("run-u7.service".into()),
                    ..good.clone()
                },
                &refs,
            ),
            (
                "no unit",
                ReattachFacts {
                    unit: None,
                    ..good.clone()
                },
                &refs,
            ),
        ];
        for (why, f, refs) in cases {
            assert!(
                known_reattach(&f, refs, &packaged, &accounts).is_err(),
                "{why}"
            );
        }
        // the packaged loader not there, the account not there
        assert!(known_reattach(&good, &refs, &|_: &str| None, &accounts).is_err());
        assert!(known_reattach(&good, &refs, &packaged, &|_: &str| None).is_err());
        // no image recorded and no packaged file: never equal
        assert!(known_reattach(
            &ReattachFacts {
                image: None,
                ..good.clone()
            },
            &refs,
            &|_: &str| None,
            &accounts
        )
        .is_err());
        // a reference of tag 0 (none is kept) proves no unread program
        assert!(known_reattach(
            &ReattachFacts {
                tag: 0,
                ..good.clone()
            },
            &[(0, 0)],
            &packaged,
            &accounts
        )
        .is_err());
        // a reference naming an entry not of the root's slot (PID 1's) proves
        // nothing
        assert!(known_reattach(
            &ReattachFacts {
                tag: 0x1111,
                ..good.clone()
            },
            &[(1, 0x1111)],
            &packaged,
            &accounts
        )
        .is_err());
        // PID 1's entry is no root program's, whatever facts match it (its
        // loader, its account, an empty unit)
        let pid1 = ReattachFacts {
            tag: 0x1111,
            exe: Some("/usr/lib/systemd/systemd".into()),
            image: Some(IMG),
            exec_uid: Some(0),
            uid: 0,
            fork_parent: Some(1),
            unit: Some(String::new()),
        };
        let both =
            |p: &str| (p == loader || p == "/usr/lib/systemd/systemd").then_some((0x801, 386_001));
        assert!(known_reattach(&pid1, &[(1, 0x1111)], &both, &accounts).is_err());
        let e = known_reattach(
            &ReattachFacts {
                tag: 0x7f3a,
                ..good
            },
            &refs,
            &packaged,
            &accounts,
        )
        .unwrap_err();
        assert!(e.contains("0000000000007f3a"), "{e}");
    }

    /// Lot 386 (named): the re-attach's facts are the lineage's as of the
    /// refusal — networkd as PID 1's unit ran it through systemd-executor
    /// (the kernel's fork record carried), as `systemd-network`, its cgroup
    /// read for the start its exec recorded: proven. The same refusal before
    /// its exec of networkd (its executor's, as of then), a root process
    /// that executed the packaged networkd itself (no fork record of PID 1),
    /// a process in another unit, a pid whose `/proc` shows another start,
    /// another tag: not proven.
    #[test]
    fn a_reattach_s_facts_are_the_lineage_s_as_of_the_refusal() {
        use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
        let t = tempfile::tempdir().unwrap();
        let s = 1_000_000_000u64;
        let loader = "/usr/lib/systemd/systemd-networkd";
        const IMG: (u64, u64) = (common::wire::exe::kernel_dev(0x801), 386_001);
        let packaged = |p: &str| (p == loader).then_some((0x801, 386_001));
        let exec = |pid: u32, path: &str, uid: u32, forker: u32, at: u64, image: (u64, u64)| {
            nn_model::Event::ProcessSpawn {
                pid,
                ppid: 1,
                uid,
                gid: uid,
                comm: "x".into(),
                filename: path.into(),
                timestamp_ns: at,
                argv: vec![path.into()],
                parent_comm: String::new(),
                parent_start_ns: 0,
                start_ns: s,
                parent_is_kthread: false,
                exe: nn_model::ExeIdentity {
                    path: path.into(),
                    dev: image.0,
                    ino: image.1,
                    flags: KNOWN | ROOT_DIR,
                    fork_parent: forker,
                    ..Default::default()
                },
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            }
        };
        let proc = t.path().join("proc");
        let entry = |pid: u32, ticks: u64, cgroup: &str| {
            let d = proc.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("stat"),
                format!(
                    "{pid} (systemd-network) S 1 {pid} {pid} 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 \
                     1 0 {ticks} 1 1\n"
                ),
            )
            .unwrap();
            std::fs::write(d.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
        };
        std::fs::create_dir_all(t.path().join("etc")).unwrap();
        std::fs::write(
            t.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n",
        )
        .unwrap();
        let unit = "/system.slice/systemd-networkd.service";
        let lineage = AuthSessionTracker::new(&proc).with_host_root(t.path());
        let executor = "/usr/lib/systemd/systemd-executor";
        // networkd at its restart: PID 1's fork, the executor, networkd
        assert!(lineage.ingest_spawn_event(&exec(1204, executor, 0, 1, 5 * s, (IMG.0, 7))));
        assert!(lineage.ingest_spawn_event(&exec(1204, loader, 998, 1, 6 * s, IMG)));
        entry(1204, 100, unit);
        // root executing the packaged networkd from its shell (pid 4242's fork)
        assert!(lineage.ingest_spawn_event(&exec(3000, loader, 998, 4242, 6 * s, IMG)));
        entry(3000, 100, unit);
        // networkd's image in another unit's cgroup
        assert!(lineage.ingest_spawn_event(&exec(3001, loader, 998, 1, 6 * s, IMG)));
        entry(3001, 100, "/system.slice/run-u7.service");
        // the pid shows another start now
        assert!(lineage.ingest_spawn_event(&exec(3002, loader, 998, 1, 6 * s, IMG)));
        entry(3002, 900, unit);
        // networkd executed as root (a drop-in's `User=`), attaching as
        // `systemd-network` once it dropped its privileges
        assert!(lineage.ingest_spawn_event(&exec(3003, loader, 0, 1, 6 * s, IMG)));
        entry(3003, 100, unit);
        // the mini-hunt: networkd in its unit's own mount namespace
        // (`ProtectSystem=`, Ubuntu 26.04: no `ROOT_DIR`), by the LSM identity
        let mut own_ns = exec(3004, loader, 998, 1, 6 * s, IMG);
        if let nn_model::Event::ProcessSpawn { exe, .. } = &mut own_ns {
            exe.flags = KNOWN;
        }
        assert!(lineage.ingest_spawn_event(&exec(3004, executor, 0, 1, 5 * s, (IMG.0, 7))));
        assert!(lineage.ingest_spawn_event(&own_ns));
        entry(3004, 100, unit);
        let refs = [(0usize, MONITOR_TAG)];
        let prove = |pid: u32, tag: u64, at: u64| {
            known_reattach_by(&lineage, &refs, &packaged, (pid, 998), tag, at)
        };
        assert_eq!(prove(1204, MONITOR_TAG, 7 * s), Ok(0));
        assert_eq!(
            prove(3004, MONITOR_TAG, 7 * s),
            Ok(0),
            "its own mount namespace"
        );
        assert!(
            prove(1204, MONITOR_TAG, 5 * s + s / 2).is_err(),
            "the executor's"
        );
        assert!(prove(1204, 0x7f3a, 7 * s).is_err(), "another program");
        assert!(prove(3000, MONITOR_TAG, 7 * s).is_err(), "not PID 1's fork");
        assert!(prove(3001, MONITOR_TAG, 7 * s).is_err(), "another unit");
        assert!(prove(3002, MONITOR_TAG, 7 * s).is_err(), "another start");
        assert!(prove(3003, MONITOR_TAG, 7 * s).is_err(), "root at the exec");
        assert!(
            known_reattach_by(&lineage, &refs, &packaged, (1204, 0), MONITOR_TAG, 7 * s).is_err(),
            "root at the attach"
        );
        assert!(prove(4040, MONITOR_TAG, 7 * s).is_err(), "no exec recorded");
    }

    /// Lot 386 (named): the reference of a re-attach is the tag of a root
    /// program the round proved loaded BEFORE the agent started — not one
    /// the hook saw loading (a window's), not an unread tag, not the LSM
    /// entry's; each once, at most `CAP`.
    #[test]
    fn a_reattach_s_reference_is_a_program_loaded_before_the_start() {
        let r = ReattachReference::new();
        let k = |entry, seen, tag| Known {
            id: 35,
            entry,
            link_id: 3,
            pid: 631,
            uid: 998,
            comm: "systemd-network".into(),
            seen,
            tag,
        };
        r.note(&k(0, true, MONITOR_TAG));
        r.note(&k(0, false, 0));
        r.note(&k(1, false, 0xe893));
        r.note(&k(7, false, 0xe893));
        assert!(r.tags().is_empty());
        r.note(&k(0, false, MONITOR_TAG));
        r.note(&k(0, false, MONITOR_TAG));
        assert_eq!(r.tags(), vec![(0, MONITOR_TAG)]);
        for t in 1..=20u64 {
            r.note(&k(0, false, t));
        }
        assert_eq!(r.tags().len(), ReattachReference::CAP);
        // the round notes each known root program it proves
        let src = include_str!("kernel_state.rs");
        let round = &src[src.find("\npub fn round(").unwrap()..];
        let round = &round[..round.find("\n}\n").unwrap()];
        assert!(
            round.contains("crate::known_system_prog::REATTACH_REFERENCE.note(k);"),
            "{round}"
        );
    }

    /// Lot 373 (the rc7 soak's `sudo bpftool prog show`): the packaged
    /// bpftool, run by root, listing or showing programs or maps, is a
    /// listing; a copy, a program of its own, a non-root run, a dump or a
    /// detach, an object of another kind is not — they keep High.
    #[test]
    fn a_root_listing_by_the_packaged_bpftool_is_told_from_a_handle_grab() {
        const IMG: (u64, u64) = (common::wire::exe::kernel_dev(0x801), 373_001);
        let tool = "/usr/lib/linux-tools-6.8.0-149/bpftool";
        let packaged =
            |p: &str| (p == tool || p == "/usr/sbin/bpftool").then_some((0x801, 373_001));
        let argv_of = |want: &'static [&'static str]| move |argv: &[&str]| argv == want;
        let prove = |exe: &str, uid: u32, argv: &'static [&'static str], kind_id: (u64, u64)| {
            bpftool_listing(
                Some(exe),
                Some(IMG),
                Some(uid),
                &argv_of(argv),
                &packaged,
                kind_id,
            )
        };
        for (argv, kind_id) in [
            (&["bpftool", "prog", "show"][..], (2, 48)),
            (&["bpftool", "prog"][..], (2, 48)),
            (&["bpftool", "-j", "prog", "list"][..], (2, 48)),
            (
                &["bpftool", "--json", "--pretty", "map", "show"][..],
                (1, 31),
            ),
            (&["bpftool", "prog", "show", "id", "48"][..], (2, 48)),
            (&["bpftool", "cgroup", "tree"][..], (2, 48)),
        ] {
            assert_eq!(
                prove(tool, 0, argv, kind_id).as_deref(),
                Ok(tool),
                "{argv:?}"
            );
        }
        assert!(prove("/usr/sbin/bpftool", 0, &["bpftool", "prog", "show"], (2, 1)).is_ok());
        // HIGH as before: what takes a usable handle, or is not the tool
        for (exe, uid, argv, kind_id, why) in [
            (
                tool,
                0,
                &["bpftool", "map", "dump", "id", "31"][..],
                (1, 31),
                "a dump",
            ),
            (
                tool,
                0,
                &["bpftool", "map", "update", "id", "31"][..],
                (1, 31),
                "an update",
            ),
            (
                tool,
                0,
                &["bpftool", "prog", "pin", "id", "48", "/sys/fs/bpf/x"][..],
                (2, 48),
                "a pin",
            ),
            (
                tool,
                0,
                &["bpftool", "prog", "show", "id", "49"][..],
                (2, 48),
                "another id",
            ),
            (
                tool,
                0,
                &["bpftool", "map", "show"][..],
                (2, 48),
                "the kind refused is a program",
            ),
            (
                tool,
                0,
                &["bpftool", "cgroup", "tree"][..],
                (1, 31),
                "a map by cgroup tree",
            ),
            (
                tool,
                1000,
                &["bpftool", "prog", "show"][..],
                (2, 48),
                "not root",
            ),
            (
                "/tmp/bpftool",
                0,
                &["bpftool", "prog", "show"][..],
                (2, 48),
                "a copy",
            ),
            (
                "/usr/bin/python3.12",
                0,
                &["bpftool", "prog", "show"][..],
                (2, 48),
                "ctypes",
            ),
        ] {
            assert!(prove(exe, uid, argv, kind_id).is_err(), "{why}");
        }
        // the file at the path is not the one it ran (replaced, a copy
        // bind-mounted over it in its namespace)
        let other = |_: &str| Some((0x801, 999));
        assert!(bpftool_listing(
            Some(tool),
            Some(IMG),
            Some(0),
            &argv_of(&["bpftool", "prog", "show"]),
            &other,
            (2, 48)
        )
        .is_err());
        assert!(bpftool_listing(
            None,
            Some(IMG),
            Some(0),
            &argv_of(&["bpftool", "prog", "show"]),
            &packaged,
            (2, 48)
        )
        .is_err());
        assert!(is_bpftool_path(
            "/usr/lib/linux-tools/6.8.0-149-generic/bpftool"
        ));
        assert!(!is_bpftool_path("/usr/lib/linux-tools-../bpftool"));
        assert!(!is_bpftool_path("/usr/lib/linux-tools-6.8/x/bpftool"));
        assert!(!is_bpftool_path("/home/u/bpftool"));
    }

    const NETWORKD: &str = "/usr/lib/systemd/systemd-networkd";
    const SYSTEMD: &str = "/usr/lib/systemd/systemd";
    const S: u64 = 1_000_000_000;
    const ROOT: KnownLink = KnownLink::RootCgroupSysctl;

    fn monitor(load_time: u64) -> Program {
        Program {
            prog_type: PROG_TYPE_CGROUP_SYSCTL,
            name: "sysctl_monitor".into(),
            attach: String::new(),
            load_time,
            tag: MONITOR_TAG,
        }
    }

    fn restrict_fs(load_time: u64) -> Program {
        Program {
            prog_type: PROG_TYPE_LSM,
            name: "restrict_filesy".into(),
            attach: "bpf_lsm_file_open".into(),
            load_time,
            tag: 0xe893_2b6b_ae2b_9745,
        }
    }

    fn networkd(pid: u32, start_ns: u64) -> Holder {
        Holder {
            pid,
            uid: 998,
            comm: "systemd-network".into(),
            start_ns,
            exe: (65025, 7176),
            link_id: 3,
        }
    }

    fn pid1() -> Holder {
        Holder {
            pid: 1,
            uid: 0,
            comm: "systemd".into(),
            start_ns: 0,
            exe: (65025, 7156),
            link_id: 2,
        }
    }

    fn pkg(path: &str) -> Option<(u64, u64)> {
        match path {
            NETWORKD => Some((65025, 7176)),
            SYSTEMD => Some((65025, 7156)),
            _ => None,
        }
    }

    fn seen_by(tgid: u32) -> SeenLoad {
        SeenLoad {
            tgid,
            uid: 998,
            prog_type: PROG_TYPE_CGROUP_SYSCTL,
            _pad: 0,
            comm: *b"systemd-network\0",
        }
    }

    /// Lot 304 (named; the brief's first test): systemd-networkd's
    /// `sysctl_monitor` as Debian 13 and Ubuntu 26.04 have it — loaded by
    /// the packaged networkd (started at 7.72 s, the load at 8 s), its link
    /// to the root held by it, before the agent's start (20 s) — is the
    /// known system program, with its proof; so is one the agent's `bpf`
    /// hook saw that process load (inside a window, after the start); and
    /// PID 1's `restrict_filesystems` LSM program, its tracing link held by
    /// PID 1 running the packaged systemd.
    #[test]
    fn a_packaged_loader_s_program_is_recognised() {
        let k = judge(
            35,
            ROOT,
            Some(&monitor(8 * S)),
            &[networkd(631, 7_720_000_000)],
            &pkg,
            Some(20 * S),
            None,
        )
        .unwrap();
        assert_eq!(
            k,
            Known {
                id: 35,
                entry: 0,
                link_id: 3,
                pid: 631,
                uid: 998,
                comm: "systemd-network".into(),
                seen: false,
                tag: MONITOR_TAG,
            }
        );
        // networkd restarted inside a window: the hook saw it load
        let k = judge(
            90,
            ROOT,
            Some(&monitor(40 * S)),
            &[networkd(2001, 39 * S)],
            &pkg,
            Some(20 * S),
            Some(&seen_by(2001)),
        )
        .unwrap();
        assert!(k.seen && k.pid == 2001, "{k:?}");
        // among other holders, the packaged one proves it
        let other = Holder {
            pid: 4000,
            exe: (65025, 1),
            ..networkd(4000, 0)
        };
        let k = judge(
            35,
            ROOT,
            Some(&monitor(8 * S)),
            &[other, networkd(631, 7 * S)],
            &pkg,
            Some(20 * S),
            None,
        )
        .unwrap();
        assert_eq!(k.pid, 631);
        // PID 1's LSM program
        let k = judge(
            21,
            KnownLink::Lsm,
            Some(&restrict_fs(2 * S)),
            &[pid1()],
            &pkg,
            Some(20 * S),
            None,
        )
        .unwrap();
        assert_eq!(
            (k.entry, k.pid, k.uid, k.link_id, k.seen),
            (1, 1, 0, 2, false)
        );
    }

    /// Lot 304 (named; the brief's second test): the same name from
    /// another loader stays what it was — whatever else holds: another
    /// executable (a copy of networkd or of systemd, a renamed tool), no
    /// holder, the packaged file not there, a holder started after the load,
    /// a load after the agent's start not seen, or seen from another
    /// process; and a program of another name, type, attach function or
    /// link kind held by the packaged loader itself.
    #[test]
    fn the_same_name_from_another_loader_is_not_known() {
        let ok = |h: &[Holder], p: &Program, seen: Option<&SeenLoad>| {
            judge(35, ROOT, Some(p), h, &pkg, Some(20 * S), seen)
        };
        let copy = Holder {
            exe: (65025, 9999),
            ..networkd(700, 7 * S)
        };
        let e = ok(&[copy], &monitor(8 * S), None).unwrap_err();
        assert!(
            e.contains("does not run /usr/lib/systemd/systemd-networkd"),
            "{e}"
        );
        let other_dev = Holder {
            exe: (1, 7176),
            ..networkd(701, 7 * S)
        };
        assert!(ok(&[other_dev], &monitor(8 * S), None).is_err());
        // PID 1 holding networkd's program: not its loader
        assert!(ok(&[pid1()], &monitor(8 * S), None).is_err());
        let e = ok(&[], &monitor(8 * S), None).unwrap_err();
        assert!(e.contains("no process holds"), "{e}");
        let e = judge(
            35,
            ROOT,
            Some(&monitor(8 * S)),
            &[networkd(631, 7 * S)],
            &|_| None,
            Some(20 * S),
            None,
        )
        .unwrap_err();
        assert!(e.contains("not there as a packaged file"), "{e}");
        let e = ok(&[networkd(631, 9 * S)], &monitor(8 * S), None).unwrap_err();
        assert!(e.contains("started after its load"), "{e}");
        // the start and the load on the same tick: still before
        assert!(ok(&[networkd(631, 8 * S)], &monitor(8 * S), None).is_ok());
        // loaded after the agent's start: only the hook's record of THAT
        // process loading it proves it
        let e = ok(&[networkd(631, 7 * S)], &monitor(21 * S), None).unwrap_err();
        assert!(e.contains("after the agent's start"), "{e}");
        let e = ok(
            &[networkd(631, 7 * S)],
            &monitor(21 * S),
            Some(&seen_by(5555)),
        )
        .unwrap_err();
        assert!(e.contains("saw pid 5555 load it"), "{e}");
        // loaded at the agent's very start: not before it
        assert!(ok(&[networkd(631, 7 * S)], &monitor(20 * S), None).is_err());
        // the agent's start unknown: nothing is before it
        assert!(judge(
            35,
            ROOT,
            Some(&monitor(8 * S)),
            &[networkd(631, 7 * S)],
            &pkg,
            None,
            None
        )
        .is_err());
        // a seen load by another process, before the start: still not known
        assert!(ok(&[networkd(631, 7 * S)], &monitor(8 * S), Some(&seen_by(42))).is_err());
        // another name, another type, no record
        let renamed = Program {
            name: "sysctl_monitox".into(),
            ..monitor(8 * S)
        };
        assert!(ok(&[networkd(631, 7 * S)], &renamed, None)
            .unwrap_err()
            .contains("is no known system program"));
        let skb = Program {
            prog_type: 8,
            ..monitor(8 * S)
        };
        assert!(ok(&[networkd(631, 7 * S)], &skb, None).is_err());
        assert!(judge(
            35,
            ROOT,
            None,
            &[networkd(631, 7 * S)],
            &pkg,
            Some(20 * S),
            None
        )
        .is_err());
        // the LSM entry: another attach function, the root's link kind, a
        // holder that is not PID 1's packaged systemd
        let elsewhere = Program {
            attach: "bpf_lsm_bprm_check_security".into(),
            ..restrict_fs(2 * S)
        };
        let lsm =
            |p: &Program, h: &[Holder], link| judge(21, link, Some(p), h, &pkg, Some(20 * S), None);
        assert!(lsm(&elsewhere, &[pid1()], KnownLink::Lsm).is_err());
        assert!(lsm(&restrict_fs(2 * S), &[pid1()], ROOT).is_err());
        assert!(lsm(&restrict_fs(2 * S), &[networkd(631, 0)], KnownLink::Lsm).is_err());
        assert!(lsm(&restrict_fs(2 * S), &[pid1()], KnownLink::Lsm).is_ok());
    }

    /// Lot 304: on the host, a program no entry names is refused by its
    /// traits before `/proc` is read; one an entry names whose link no
    /// process holds is not known either; no record, no judgement.
    #[test]
    fn on_the_host_a_program_needs_its_traits_and_its_holder() {
        let e = judge_on_host(
            u32::MAX,
            ROOT,
            Some(&Program {
                name: "x".into(),
                ..monitor(1)
            }),
            Some(u64::MAX),
            None,
        )
        .unwrap_err();
        assert!(e.contains("is no known system program"), "{e}");
        assert!(judge_on_host(u32::MAX, ROOT, Some(&monitor(1)), Some(u64::MAX), None).is_err());
        assert!(judge_on_host(
            u32::MAX,
            KnownLink::Lsm,
            Some(&restrict_fs(1)),
            Some(u64::MAX),
            None
        )
        .is_err());
        let e = judge_on_host(u32::MAX, ROOT, None, Some(u64::MAX), None).unwrap_err();
        assert!(e.contains("not in the BPF enumeration"), "{e}");
        assert!(agent_start_ns().is_some());
        assert!(clk_tck() > 0);
    }

    /// Lot 304: a BPF link's fdinfo, as 6.12 and 7.0 print it (the lab's
    /// guests): the link of THAT program to the ROOT cgroup as
    /// `cgroup_sysctl`, or THAT program's LSM tracing link, only.
    #[test]
    fn the_holder_s_link_is_read_from_fdinfo() {
        let text = "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t2080\nlink_type:\tcgroup\n\
                    link_id:\t3\nprog_tag:\t342fe7f347490662\nprog_id:\t35\ncgroup_id:\t1\n\
                    attach_type:\t18\n";
        let l = parse_link_fdinfo(text);
        assert_eq!(
            l,
            LinkInfo {
                link_type: "cgroup".into(),
                link_id: 3,
                prog_id: 35,
                cgroup_id: Some(1),
                attach_type: Some(18),
            }
        );
        assert!(l.attaches(35, ROOT));
        assert!(!l.attaches(35, KnownLink::Lsm));
        // a link whose program is gone (no prog_id, read as 0) is no one's
        let detached = parse_link_fdinfo(&text.replace("prog_id:\t35\n", ""));
        assert_eq!(detached.prog_id, 0);
        assert!(!detached.attaches(0, ROOT));
        assert!(!l.attaches(36, ROOT));
        assert!(!l.attaches(0, ROOT));
        for (from, to) in [
            ("link_type:\tcgroup", "link_type:\titer"),
            ("cgroup_id:\t1", "cgroup_id:\t2"),
            ("attach_type:\t18", "attach_type:\t17"),
            ("prog_id:\t35", "prog_id:\t350"),
            ("cgroup_id:\t1\n", ""),
            ("attach_type:\t18\n", ""),
        ] {
            let changed = text.replace(from, to);
            assert_ne!(changed, text);
            assert!(
                !parse_link_fdinfo(&changed).attaches(35, ROOT),
                "{from} -> {to}"
            );
        }
        // PID 1's restrict_filesystems link on the debian13 guest
        let lsm = "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t1063\nlink_type:\ttracing\n\
                   link_id:\t2\nprog_tag:\te8932b6bae2b9745\nprog_id:\t21\nattach_type:\t27\n\
                   target_obj_id:\t1\ntarget_btf_id:\t55789\n";
        let l = parse_link_fdinfo(lsm);
        assert!(l.attaches(21, KnownLink::Lsm) && l.link_id == 2);
        assert!(!l.attaches(21, ROOT));
        assert!(!l.attaches(22, KnownLink::Lsm));
        for (from, to) in [
            ("link_type:\ttracing", "link_type:\tcgroup"),
            ("attach_type:\t27", "attach_type:\t26"),
            ("attach_type:\t27\n", ""),
        ] {
            assert!(
                !parse_link_fdinfo(&lsm.replace(from, to)).attaches(21, KnownLink::Lsm),
                "{to}"
            );
        }
    }

    fn proc_entry(proc: &Path, pid: u32, exe: &Path, fds: &[(&str, &str)], start_ticks: u64) {
        let d = proc.join(pid.to_string());
        std::fs::create_dir_all(d.join("fd")).unwrap();
        std::fs::create_dir_all(d.join("fdinfo")).unwrap();
        std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
        std::fs::write(
            d.join("stat"),
            format!(
                "{pid} (systemd-network) S 1 {pid} {pid} 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 \
                 {start_ticks} 1 1\n"
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("status"),
            "Name:\tsystemd-network\nUid:\t998\t998\t998\t998\n",
        )
        .unwrap();
        std::fs::write(d.join("comm"), "systemd-network\n").unwrap();
        for (i, (target, info)) in fds.iter().enumerate() {
            std::os::unix::fs::symlink(target, d.join("fd").join(i.to_string())).unwrap();
            std::fs::write(d.join("fdinfo").join(i.to_string()), info).unwrap();
        }
    }

    /// Lot 340 (named): a refused probe's loader is proven a known system
    /// probe's — it runs the packaged loader of an entry for that program
    /// type, the same process at both reads, started before the load. A
    /// copy of the loader, another type, a process started after the load,
    /// a pid with no process: not proven (the record keeps High).
    #[test]
    fn a_known_probe_s_loader_is_proven_by_its_packaged_image() {
        use common::bpf_prog_class::{
            PROG_TYPE_EXT, PROG_TYPE_KPROBE, PROG_TYPE_LSM, PROG_TYPE_PERF_EVENT,
            PROG_TYPE_TRACEPOINT,
        };
        let t = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(t.path()).unwrap().uid();
        let file = |rel: &str| {
            let bin = t.path().join(rel);
            std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
            std::fs::write(&bin, b"\x7fELF").unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            bin
        };
        let networkd = file("usr/lib/systemd/systemd-networkd");
        let systemd = file("usr/lib/systemd/systemd");
        let copy = file("tmp/systemd-networkd");
        let packaged = |p: &str| super::packaged(t.path(), p, me);
        // the review of #552 (F5a): the image the loader's exec recorded,
        // in the kernel's form
        let image = |f: &Path| {
            let m = std::fs::metadata(f).unwrap();
            Some((common::wire::exe::kernel_dev(m.dev()), m.ino()))
        };
        let probe = |img, pid, ty| known_probe(img, &packaged, pid, ty);
        assert_eq!(probe(image(&networkd), 868, PROG_TYPE_KPROBE), Ok(1));
        assert_eq!(probe(image(&systemd), 2301, PROG_TYPE_TRACEPOINT), Ok(0));
        // the coordinator's rule: systemd's own loads of the types its
        // programs use
        assert_eq!(probe(image(&networkd), 868, PROG_TYPE_TRACEPOINT), Ok(2));
        assert_eq!(probe(image(&systemd), 2301, PROG_TYPE_KPROBE), Ok(3));
        // the review of #552 (F5b): `lsm` is PID 1's (the input: PID 1)
        assert_eq!(probe(image(&systemd), 1, PROG_TYPE_LSM), Ok(4));
        for (img, pid, ty) in [
            (image(&copy), 4242, PROG_TYPE_KPROBE),
            (image(&copy), 4242, PROG_TYPE_TRACEPOINT),
            (image(&networkd), 868, PROG_TYPE_LSM),
            (image(&systemd), 2301, PROG_TYPE_EXT),
            (image(&systemd), 2301, PROG_TYPE_PERF_EVENT),
            (image(&systemd), 2301, PROG_TYPE_LSM),
            (None, 999, PROG_TYPE_KPROBE),
        ] {
            assert!(probe(img, pid, ty).is_err(), "pid {pid} type {ty}");
        }
        // a loader file another user may write is no packaged one
        std::fs::set_permissions(&networkd, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(probe(image(&networkd), 868, PROG_TYPE_KPROBE).is_err());
    }

    /// Named test (the review of #552, F5a): a refused load is proven a
    /// known probe's by the image its loader ran WHEN IT LOADED — its exec
    /// record as of the load. A root process that loads a `kprobe` program
    /// (refused) and executes the packaged systemd at once showed systemd's
    /// image in `/proc` as the record was decoded (AT-001 Low, no posture);
    /// as of the load it ran its own program: not proven. A load before any
    /// recorded exec of its loader (only a later one known) is not proven
    /// either; the packaged loader that executed before its load is.
    #[test]
    fn a_known_probe_is_proven_by_the_loader_s_image_at_the_load() {
        use common::bpf_prog_class::PROG_TYPE_KPROBE;
        use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
        let t = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(t.path()).unwrap().uid();
        let systemd = t.path().join("usr/lib/systemd/systemd");
        std::fs::create_dir_all(systemd.parent().unwrap()).unwrap();
        std::fs::write(&systemd, b"\x7fELF").unwrap();
        std::fs::set_permissions(&systemd, std::fs::Permissions::from_mode(0o755)).unwrap();
        let m = std::fs::metadata(&systemd).unwrap();
        let packaged_image = (common::wire::exe::kernel_dev(m.dev()), m.ino());
        let s = 1_000_000_000u64;
        let exec =
            |pid: u32, path: &str, image: (u64, u64), at: u64| nn_model::Event::ProcessSpawn {
                pid,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm: "x".into(),
                filename: path.into(),
                timestamp_ns: at,
                argv: vec![path.into()],
                parent_comm: String::new(),
                parent_start_ns: 0,
                start_ns: s,
                parent_is_kthread: false,
                exe: nn_model::ExeIdentity {
                    path: path.into(),
                    dev: image.0,
                    ino: image.1,
                    flags: KNOWN | ROOT_DIR,
                    fork_parent: 1,
                    ..Default::default()
                },
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            };
        let lineage = AuthSessionTracker::new(t.path().join("proc"));
        // networkd: the packaged binary in its unit's own mount namespace
        // (`ProtectSystem=`: no `ROOT_DIR`, the LSM identity all the same)
        let mut networkd = exec(868, "/usr/lib/systemd/systemd", packaged_image, 5 * s);
        if let nn_model::Event::ProcessSpawn { exe, .. } = &mut networkd {
            exe.flags = KNOWN;
        }
        assert!(lineage.ingest_spawn_event(&networkd));
        // the user manager: the packaged systemd since 5 s, its load at 9 s
        assert!(lineage.ingest_spawn_event(&exec(
            2301,
            "/usr/lib/systemd/systemd",
            packaged_image,
            5 * s
        )));
        // the attack: its own program at 5 s, the load at 9 s, the packaged
        // systemd executed at 9.5 s (before the record is decoded)
        assert!(lineage.ingest_spawn_event(&exec(3000, "/tmp/x", (packaged_image.0, 77), 5 * s)));
        assert!(lineage.ingest_spawn_event(&exec(
            3000,
            "/usr/lib/systemd/systemd",
            packaged_image,
            9 * s + s / 2
        )));
        // a loader whose only recorded exec is later than its load
        assert!(lineage.ingest_spawn_event(&exec(
            3001,
            "/usr/lib/systemd/systemd",
            packaged_image,
            9 * s + s / 2
        )));
        let packaged = |p: &str| super::packaged(t.path(), p, me);
        let probe = |pid| known_probe_by(&lineage, &packaged, pid, PROG_TYPE_KPROBE, 9 * s);
        assert_eq!(probe(2301), Ok(3));
        assert_eq!(probe(868), Ok(3), "in a mount namespace of its own");
        assert!(probe(3000).is_err(), "its own program at the load");
        assert!(probe(3001).is_err(), "no exec recorded as of the load");
        assert_eq!(
            known_probe_by(&lineage, &packaged, 3000, PROG_TYPE_KPROBE, 10 * s),
            Ok(3),
            "a load after its exec of the packaged systemd"
        );
    }

    /// Lot 304: a process whose start is not the same at the second read
    /// (its pid reused during the scan) is no holder; the same start both
    /// times, it is.
    #[test]
    fn a_pid_reused_during_the_scan_is_no_holder() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("networkd");
        std::fs::write(&bin, b"\x7fELF").unwrap();
        let proc = t.path().join("proc");
        let link =
            "link_type:\tcgroup\nlink_id:\t3\nprog_id:\t35\ncgroup_id:\t1\nattach_type:\t18\n";
        proc_entry(&proc, 631, &bin, &[("anon_inode:bpf_link", link)], 772);
        let reads = std::cell::Cell::new(0);
        let stat = |start: u64| {
            format!(
                "631 (systemd-network) S 1 631 631 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 {start} 1 1\n"
            )
        };
        // the second read another start
        let reused = |p: &Path| {
            reads.set(reads.get() + 1);
            p.ends_with("631/stat")
                .then(|| stat(if reads.get() == 1 { 772 } else { 905 }))
        };
        let h = holders_by(&proc, 35, ROOT, 100, &reused);
        assert!(h.is_empty(), "another start at the second read: {h:?}");
        assert_eq!(reads.get(), 2, "read before and after");
        let same = |p: &Path| p.ends_with("631/stat").then(|| stat(772));
        let h = holders_by(&proc, 35, ROOT, 100, &same);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].start_ns, 7_720_000_000);
    }

    /// Lot 304: the holders are read from `/proc` — the process holding a
    /// BPF link of the program the entry's way, with its executable's
    /// device and inode, its real uid and its start; a descriptor that is
    /// not a BPF link, or a link of another program, cgroup or attach type,
    /// makes no holder; and the packaged file is one owned by its owner and
    /// writable by no one else.
    #[test]
    fn the_holders_are_read_from_proc() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("usr/lib/systemd/systemd-networkd");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"\x7fELF").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let other = t.path().join("tmp-networkd");
        std::fs::write(&other, b"\x7fELF").unwrap();
        let proc = t.path().join("proc");
        let link = |prog: u32, cg: u32, at: u32| {
            format!(
                "link_type:\tcgroup\nlink_id:\t3\nprog_id:\t{prog}\ncgroup_id:\t{cg}\n\
                 attach_type:\t{at}\n"
            )
        };
        proc_entry(
            &proc,
            631,
            &bin,
            &[
                ("anon_inode:bpf-prog", "prog_type:\t23\nprog_id:\t35\n"),
                ("anon_inode:bpf_link", &link(35, 1, 18)),
            ],
            772,
        );
        // the right link's text behind a descriptor that is no BPF link
        proc_entry(&proc, 700, &other, &[("/dev/null", &link(35, 1, 18))], 800);
        // links of another program, another cgroup, another attach type
        proc_entry(
            &proc,
            701,
            &other,
            &[
                ("anon_inode:bpf_link", &link(36, 1, 18)),
                ("anon_inode:bpf_link", &link(35, 2, 18)),
                ("anon_inode:bpf_link", &link(35, 1, 17)),
            ],
            800,
        );
        // a copy holding the root link
        proc_entry(
            &proc,
            702,
            &other,
            &[("anon_inode:bpf_link", &link(35, 1, 18))],
            900,
        );
        std::fs::create_dir_all(proc.join("self")).unwrap();
        let h = holders(&proc, 35, ROOT, 100);
        let m = std::fs::metadata(&bin).unwrap();
        let o = std::fs::metadata(&other).unwrap();
        assert_eq!(
            h,
            vec![
                Holder {
                    pid: 631,
                    uid: 998,
                    comm: "systemd-network".into(),
                    start_ns: 7_720_000_000,
                    exe: (m.dev(), m.ino()),
                    link_id: 3,
                },
                Holder {
                    pid: 702,
                    uid: 998,
                    comm: "systemd-network".into(),
                    start_ns: 9_000_000_000,
                    exe: (o.dev(), o.ino()),
                    link_id: 3,
                },
            ]
        );
        assert!(holders(&proc, 0, ROOT, 100).is_empty());
        // the same links are no LSM program's
        assert!(holders(&proc, 35, KnownLink::Lsm, 100).is_empty());
        // the packaged file: its owner's, writable by no one else
        let me = m.uid();
        assert_eq!(packaged(t.path(), NETWORKD, me), Some((m.dev(), m.ino())));
        assert_eq!(packaged(t.path(), NETWORKD, me + 1), None);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(packaged(t.path(), NETWORKD, me), None);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert_eq!(packaged(t.path(), NETWORKD, me), None);
        // a directory, its mode as closed as the file's, is none
        let dir = t.path().join("usr/lib/systemd");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(packaged(t.path(), "/usr/lib/systemd", me), None);
        assert_eq!(packaged(t.path(), "/usr/lib/nothing", me), None);
        // the whole judgement over that /proc: the packaged holder proves it
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let k = judge(
            35,
            ROOT,
            Some(&monitor(8 * S)),
            &h,
            &|p| packaged(t.path(), p, me),
            Some(20 * S),
            None,
        )
        .unwrap();
        assert_eq!((k.pid, k.link_id, k.seen), (631, 3, false));
        // and through the host's reader, from that /proc and that root
        let host = Host {
            proc: &proc,
            root: t.path(),
            owner: me,
            clk_tck: 100,
        };
        let k = host
            .judge(35, ROOT, Some(&monitor(8 * S)), Some(20 * S), None)
            .unwrap();
        assert_eq!(
            (k.pid, k.uid, k.link_id, k.comm.as_str()),
            (631, 998, 3, "systemd-network")
        );
        // a name no entry has: no holder read, not known
        let e = host
            .judge(
                35,
                ROOT,
                Some(&Program {
                    name: "other".into(),
                    ..monitor(8 * S)
                }),
                Some(20 * S),
                None,
            )
            .unwrap_err();
        assert!(e.contains("is no known system program"), "{e}");
        // the LSM kind: no such link there
        assert!(host
            .judge(
                35,
                KnownLink::Lsm,
                Some(&restrict_fs(8 * S)),
                Some(20 * S),
                None
            )
            .is_err());
    }

    /// Lot 311 (N6): a loader whose `comm` is not UTF-8 has its real uid
    /// and start read; on main neither was.
    #[test]
    fn a_loader_whose_comm_is_not_utf8_has_its_uid_and_start() {
        let t = tempfile::tempdir().unwrap();
        crate::state_read::testing::write_non_utf8_proc(t.path(), 4303, 1, 0, 100);
        let pdir = t.path().join("4303");
        assert_eq!(real_uid(&pdir), Some(0));
        assert!(start_ns(&pdir, 100).is_some());
    }
}
