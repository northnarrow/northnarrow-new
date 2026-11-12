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
        });
    }
    Err(why.join("; "))
}

/// `(device, inode)` of the packaged file at `path` under `root` (`/`): a
/// regular file owned by `owner` (root) and writable by no one else, links
/// followed.
pub fn packaged(root: &Path, path: &str, owner: u32) -> Option<(u64, u64)> {
    let m = std::fs::metadata(root.join(path.trim_start_matches('/'))).ok()?;
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
    let fds = std::fs::read_dir(pdir.join("fd")).ok()?;
    for fd in fds.flatten() {
        let is_link = std::fs::read_link(fd.path())
            .is_ok_and(|t| t.as_os_str().as_encoded_bytes() == b"anon_inode:bpf_link");
        if !is_link {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(pdir.join("fdinfo").join(fd.file_name())) else {
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
    let Ok(dir) = std::fs::read_dir(proc) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let pdir = e.path();
        let Some(start) = start_ns_by(&pdir, clk_tck, read_stat) else {
            continue;
        };
        let Some(link_id) = held_link(&pdir, id, link) else {
            continue;
        };
        let (Ok(exe), Some(uid)) = (std::fs::metadata(pdir.join("exe")), real_uid(&pdir)) else {
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
        }
    }

    fn restrict_fs(load_time: u64) -> Program {
        Program {
            prog_type: PROG_TYPE_LSM,
            name: "restrict_filesy".into(),
            attach: "bpf_lsm_file_open".into(),
            load_time,
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
