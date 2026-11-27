//! Lot 2.2 (the review of #644): what the agent watches around its roles,
//! beside the kernel's refusals.
//!
//! * **A preloaded library** (F3). `/etc/ld.so.preload` makes the loader
//!   map a library into every process at its exec, the agent's and the
//!   watchdog's included. The kernel judges it at that mapping like any
//!   other (`common::exec_marks::code_verdict`): one that fails the test
//!   takes the role away (signed by the kernel); one that passes keeps the
//!   role — a host's own preload (an audit or APM library) — and the agent
//!   signs a High advisory per library and role process
//!   ([`PRELOAD_KIND`]), listed by `nn-admin status` while it holds. The
//!   file is read as the loader reads it ([`preload_tokens`]: blanks and
//!   `:` separate names; `$LIB` and `$PLATFORM` stand for the loader's
//!   directories, [`preload_expansions`]). Refusing a write of the file
//!   outside a window is lot 2.7's.
//! * **The cgroup BPF census** (F4). The `bpf` hook refuses a cgroup
//!   program attached to the agent's cgroups outside a window, judged on
//!   the descriptor it reads; the kernel resolves the descriptor again
//!   after the hook (`cgroup_get_from_fd`), and no hook follows that
//!   resolution where a refusal could be made. So the agent asks the
//!   kernel what is attached ([`census`]: `BPF_PROG_QUERY` of every cgroup
//!   attach type on the root cgroup, `northnarrow.slice` and the cgroups
//!   below it), at its start, every round of the link self-check
//!   ([`super::bpf_defense::LINK_CHECK_SECS`]: a window's close within it)
//!   and right after each cgroup attach the kernel let through
//!   ([`census_soon`]). Every program that is not the agent's own is
//!   signed High once while it stays ([`CGROUP_FOREIGN_KIND`]) and counted
//!   in `nn-admin status`. Nothing is detached: a program the host's
//!   operator attached stays until the operator decides (a detach on the
//!   operator's request is a follow-up).

use std::collections::BTreeSet;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::self_integrity::Finding;

/// The advisory's kind: a preloaded library mapped into a role process.
pub const PRELOAD_KIND: &str = "role_preloaded_library";
/// The census's kind: a cgroup BPF program not the agent's on its cgroups.
pub const CGROUP_FOREIGN_KIND: &str = "cgroup_bpf_foreign";
/// The loader's preload list.
pub const PRELOAD_FILE: &str = "/etc/ld.so.preload";
/// The agent's units' slice, below the root cgroup.
pub const SLICE: &str = "northnarrow.slice";
/// The cgroups below the slice the census asks at most (the units', and
/// what is below them).
pub const MAX_CGROUPS: usize = 64;

/// What `$LIB` stands for in the loader of the distributions we ship for
/// (Debian's multiarch directories, the `lib64` of the RPM ones).
const LIB_EXPANSIONS: [&str; 7] = [
    "lib",
    "lib64",
    "lib32",
    "libx32",
    "lib/x86_64-linux-gnu",
    "lib/aarch64-linux-gnu",
    "lib/i386-linux-gnu",
];
/// What `$PLATFORM` stands for (x86-64's and arm64's names).
const PLATFORM_EXPANSIONS: [&str; 4] = ["x86_64", "haswell", "xeon_phi", "aarch64"];

/// The names `/etc/ld.so.preload`'s text holds, as the loader splits it
/// (glibc's `rtld.c`: space, tab, newline and `:` separate them).
pub fn preload_tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| c == ':' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
        .filter(|t| !t.is_empty())
        .collect()
}

/// The names one preload token can stand for: itself, its `$LIB` and
/// `$PLATFORM` (and `${LIB}`, `${PLATFORM}`) replaced by each of the
/// loader's values. A token without them is its own only expansion.
pub fn preload_expansions(token: &str) -> Vec<String> {
    let mut out = vec![token.to_string()];
    for (dst, values) in [
        ("LIB", &LIB_EXPANSIONS[..]),
        ("PLATFORM", &PLATFORM_EXPANSIONS[..]),
    ] {
        let forms = [format!("${{{dst}}}"), format!("${dst}")];
        let mut next = Vec::new();
        for name in &out {
            match forms.iter().find(|f| name.contains(f.as_str())) {
                Some(form) => {
                    for v in values {
                        next.push(name.replace(form.as_str(), v));
                    }
                }
                None => next.push(name.clone()),
            }
        }
        out = next;
    }
    out
}

/// One executable file mapping of a `/proc/<pid>/maps` line: its path
/// (without the kernel's ` (deleted)`), its device as `stat` gives it, and
/// its inode.
pub fn exec_file_mapping(line: &str) -> Option<(&str, u64, u64)> {
    let mut f = line.splitn(6, ' ');
    let _range = f.next()?;
    let perms = f.next()?;
    let _off = f.next()?;
    let dev = f.next()?;
    let ino: u64 = f.next()?.parse().ok()?;
    let path = f.next()?.trim_start();
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    if perms.as_bytes().get(2) != Some(&b'x') || ino == 0 || !path.starts_with('/') {
        return None;
    }
    let (maj, min) = dev.split_once(':')?;
    let (maj, min) = (
        u32::from_str_radix(maj, 16).ok()?,
        u32::from_str_radix(min, 16).ok()?,
    );
    Some((path, libc::makedev(maj, min), ino))
}

/// The executable mappings of `maps` (a `/proc/<pid>/maps` text) that a
/// preload token of `preload` (the file's text) names — by the file the
/// token's path gives (`stat`: device and inode, a link followed) or by
/// its last component (a bare name the loader looks up in its
/// directories, a link's name). Each path once.
pub fn preloaded_mappings(
    maps: &str,
    preload: &str,
    stat: impl Fn(&str) -> Option<(u64, u64)>,
) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut files: BTreeSet<(u64, u64)> = BTreeSet::new();
    for token in preload_tokens(preload) {
        for name in preload_expansions(token) {
            if let Some(last) = name.rsplit('/').next().filter(|l| !l.is_empty()) {
                names.insert(last.to_string());
            }
            if name.contains('/') {
                if let Some(id) = stat(&name) {
                    files.insert(id);
                }
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for (path, dev, ino) in maps.lines().filter_map(exec_file_mapping) {
        let base = path.rsplit('/').next().unwrap_or(path);
        if (names.contains(base) || files.contains(&(dev, ino))) && !out.iter().any(|p| p == path) {
            out.push(path.to_string());
        }
    }
    out
}

/// The advisories now: a library `/etc/ld.so.preload` names mapped into
/// the agent (this process) or the live watchdog (`watchdog_pid`).
pub fn preload_findings(watchdog_pid: Option<u32>) -> Vec<Finding> {
    let read = |p: &str| antitamper_bpf::kernel_roots::read_to_string(p).ok();
    let Some(preload) = read(PRELOAD_FILE).filter(|t| !preload_tokens(t).is_empty()) else {
        return Vec::new();
    };
    let stat = |p: &str| {
        antitamper_bpf::kernel_roots::metadata(p)
            .ok()
            .map(|m| (m.dev(), m.ino()))
    };
    let mut roles = vec![("agent", std::process::id())];
    if let Some(pid) = watchdog_pid.filter(|p| *p != 0 && *p != common::wire::ROLE_VACATED) {
        roles.push(("watchdog", pid));
    }
    let mut out = Vec::new();
    for (role, pid) in roles {
        let Some(maps) = read(&format!("/proc/{pid}/maps")) else {
            continue;
        };
        for path in preloaded_mappings(&maps, &preload, stat) {
            out.push(Finding {
                kind: PRELOAD_KIND,
                detail: preload_detail(role, &path),
            });
        }
    }
    out
}

/// The advisory's line for `path` in the role process `role`.
pub fn preload_detail(role: &str, path: &str) -> String {
    format!(
        "a preloaded library is mapped into the {role}: {path} ({PRELOAD_FILE} names it). The \
         kernel judged it when it was mapped: trusted code keeps the role (this advisory), any \
         other takes it away (a role_unmarked record)"
    )
}

/// One program the census found: where, of which attach type, its id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CensusHit {
    pub cgroup: String,
    pub attach: &'static str,
    pub prog_id: u32,
}

/// The census of `targets` (a cgroup's name and its open directory's
/// descriptor): every attach type of `common::bpf_cmd::CGROUP_ATTACH_TYPES`
/// asked through `query`; a type the kernel does not know (`EINVAL`) or a
/// cgroup it cannot ask is skipped. The programs not in `own`, sorted.
pub fn census_with(
    targets: &[(String, i32)],
    query: impl Fn(i32, u32) -> std::io::Result<Vec<u32>>,
    own: &BTreeSet<u32>,
) -> Vec<CensusHit> {
    let mut hits = Vec::new();
    for (cgroup, fd) in targets {
        for (attach, t, _) in common::bpf_cmd::CGROUP_ATTACH_TYPES {
            let Ok(ids) = query(*fd, t) else {
                continue;
            };
            for prog_id in ids {
                if !own.contains(&prog_id) {
                    hits.push(CensusHit {
                        cgroup: cgroup.clone(),
                        attach,
                        prog_id,
                    });
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// The cgroups the census asks: the root cgroup (the slice's ancestor),
/// `northnarrow.slice` and, below it, the units' cgroups and theirs, at
/// most [`MAX_CGROUPS`] — opened beneath the cgroup2 root the start
/// anchored (`antitamper_bpf::kernel_roots::cgroup_root`).
fn census_targets() -> Result<Vec<(String, std::fs::File)>, String> {
    let (root, _) = antitamper_bpf::kernel_roots::cgroup_root()?;
    let base = format!("/proc/self/fd/{}", root.as_raw_fd());
    let mut out: Vec<(String, std::fs::File)> = Vec::new();
    let mut walk: Vec<String> = vec![SLICE.to_string()];
    while let Some(rel) = walk.pop() {
        let Ok(dir) = std::fs::File::open(format!("{base}/{rel}")) else {
            continue;
        };
        if out.len() < MAX_CGROUPS {
            if let Ok(entries) = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())) {
                for e in entries.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) && rel.matches('/').count() < 2 {
                        walk.push(format!("{rel}/{}", e.file_name().to_string_lossy()));
                    }
                }
            }
            out.push((format!("/{rel}"), dir));
        }
    }
    out.push(("/ (the root cgroup)".to_string(), root));
    Ok(out)
}

/// The census now ([`census_with`] on [`census_targets`]), or why it could
/// not be made.
pub fn census(own: &BTreeSet<u32>) -> Result<Vec<CensusHit>, String> {
    let targets = census_targets()?;
    let fds: Vec<(String, i32)> = targets
        .iter()
        .map(|(n, f)| (n.clone(), f.as_raw_fd()))
        .collect();
    Ok(census_with(
        &fds,
        |fd, t| crate::sysctl_cgroup::query_cgroup(fd, t).map(|q| q.prog_ids),
        own,
    ))
}

/// The census's line for one program (`name`: what the kernel says of it,
/// when it could be read).
pub fn census_detail(hit: &CensusHit, name: Option<&str>) -> String {
    let named = name.map_or(String::new(), |n| format!(" `{n}`"));
    format!(
        "a cgroup BPF program that is not the agent's (id {}{named}) is attached to {} ({}): \
         attached before the agent started, inside a trusted-installer window, or past the \
         bpf hook's check of its descriptor — not detached (the operator decides)",
        hit.prog_id, hit.cgroup, hit.attach
    )
}

/// The foreign programs the last census found (`nn-admin status`), or
/// [`NO_CENSUS`] before the first.
static FOREIGN: AtomicU32 = AtomicU32::new(NO_CENSUS);
/// [`FOREIGN`] before any census.
pub const NO_CENSUS: u32 = u32::MAX;
/// The preloaded libraries the last round found mapped into a role
/// process.
static PRELOADED: AtomicU32 = AtomicU32::new(0);

/// The census's count for `nn-admin status`: `None` before the first.
pub fn foreign_now() -> Option<u32> {
    Some(FOREIGN.load(Ordering::SeqCst)).filter(|n| *n != NO_CENSUS)
}

/// The preload advisories' count for `nn-admin status`.
pub fn preloaded_now() -> u32 {
    PRELOADED.load(Ordering::SeqCst)
}

pub(crate) fn set_counts(foreign: Option<u32>, preloaded: u32) {
    if let Some(n) = foreign {
        FOREIGN.store(n, Ordering::SeqCst);
    }
    PRELOADED.store(preloaded, Ordering::SeqCst);
}

/// Wakes the link self-check's round early ([`census_soon`]).
static SOON: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// A cgroup attach the kernel let through (the `bpf` ring's row): the
/// census runs at once, not at the round's next turn.
pub fn census_soon() {
    SOON.notify_one();
}

/// The round's wait: `period`, or until [`census_soon`] (then a moment, so
/// that the attach the row announced has completed).
pub async fn wait_round(period: std::time::Duration) {
    tokio::select! {
        () = tokio::time::sleep(period) => {}
        () = SOON.notified() => {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}

/// Whether a `bpf` ring row of `cmd` and `arg` is a cgroup attach the
/// kernel let through (the census then runs at once).
pub fn is_cgroup_attach_row(cmd: u32, arg: u32) -> bool {
    common::bpf_cmd::judges_cgroup_attach(cmd, arg)
}

/// The findings signed so far this run, by line: a finding is signed once
/// while it holds, and again if it comes back after it was gone.
#[derive(Default)]
pub struct Signed(BTreeSet<(String, String)>);

impl Signed {
    /// The findings of `now` not signed yet (to sign), and those signed
    /// before that `now` no longer holds (their end to sign: the status
    /// lists an advisory until its `cleared` row); the set kept to `now`'s.
    /// `kept` names the kinds whose findings could not be looked for this
    /// round (a census that failed): theirs are neither fresh nor gone.
    pub fn fresh<'a>(&mut self, now: &'a [Finding], kept: &[&str]) -> (Vec<&'a Finding>, Vec<Finding>) {
        let mut lines: BTreeSet<(String, String)> = now.iter().map(key).collect();
        let fresh = now.iter().filter(|f| !self.0.contains(&key(f))).collect();
        let mut gone = Vec::new();
        for (kind, detail) in &self.0 {
            if lines.contains(&(kind.clone(), detail.clone())) {
                continue;
            }
            match [PRELOAD_KIND, CGROUP_FOREIGN_KIND].into_iter().find(|k| k == kind) {
                Some(k) if kept.contains(&k) => {
                    lines.insert((kind.clone(), detail.clone()));
                }
                Some(k) => gone.push(Finding {
                    kind: k,
                    detail: detail.clone(),
                }),
                None => {}
            }
        }
        self.0 = lines;
        (fresh, gone)
    }
}

fn key(f: &Finding) -> (String, String) {
    (f.kind.to_string(), f.detail.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F3: the loader's own split — blanks, newlines and `:` — and its
    /// `$LIB`/`$PLATFORM` spellings, braced or not.
    #[test]
    fn the_preload_file_is_read_as_the_loader_reads_it() {
        assert_eq!(
            preload_tokens("/usr/lib/a.so:/usr/lib/b.so\n\t libc.so  /x/$LIB/c.so\n"),
            ["/usr/lib/a.so", "/usr/lib/b.so", "libc.so", "/x/$LIB/c.so"]
        );
        assert!(preload_tokens(" \n:\t").is_empty());
        let e = preload_expansions("/usr/$LIB/libsnoopy.so");
        assert!(e.contains(&"/usr/lib/x86_64-linux-gnu/libsnoopy.so".to_string()));
        assert!(e.contains(&"/usr/lib64/libsnoopy.so".to_string()));
        assert_eq!(e.len(), LIB_EXPANSIONS.len());
        let e = preload_expansions("/opt/${LIB}/${PLATFORM}/x.so");
        assert!(e.contains(&"/opt/lib64/haswell/x.so".to_string()));
        assert_eq!(e.len(), LIB_EXPANSIONS.len() * PLATFORM_EXPANSIONS.len());
        assert_eq!(preload_expansions("/plain/x.so"), ["/plain/x.so"]);
    }

    const MAPS: &str = "\
7f00-7f10 r--p 00000000 08:01 1111 /usr/lib/x86_64-linux-gnu/libsnoopy.so.0.0.0
7f10-7f20 r-xp 00001000 08:01 1111 /usr/lib/x86_64-linux-gnu/libsnoopy.so.0.0.0
7f20-7f30 r-xp 00001000 08:01 2222 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)
7f30-7f40 r-xp 00001000 08:01 3333 /opt/apm/libapm.so
7f40-7f50 rw-p 00000000 00:00 0
7f50-7f60 r-xp 00000000 00:00 0 [vdso]
";

    /// F3: a preloaded library is found among the role's executable
    /// mappings by its file (a link's target) or by its name, a deleted
    /// one too; a library the file does not name is not.
    #[test]
    fn a_preloaded_library_is_found_among_the_role_s_mappings() {
        let stat = |p: &str| match p {
            "/etc/snoopy.so" => Some((libc::makedev(8, 1), 1111)),
            _ => None,
        };
        assert_eq!(
            preloaded_mappings(MAPS, "/etc/snoopy.so", stat),
            ["/usr/lib/x86_64-linux-gnu/libsnoopy.so.0.0.0"]
        );
        assert_eq!(
            preloaded_mappings(MAPS, "libapm.so:/nope/libc.so.6", stat),
            [
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/opt/apm/libapm.so"
            ]
        );
        assert_eq!(
            preloaded_mappings(MAPS, "/opt/$LIB/libapm.so", |_| None),
            ["/opt/apm/libapm.so"]
        );
        assert!(preloaded_mappings(MAPS, "/usr/lib/libother.so", stat).is_empty());
        assert!(preloaded_mappings(MAPS, "", stat).is_empty());
        // another device, the same inode: not that file
        let other_dev = |_: &str| Some((libc::makedev(8, 2), 1111));
        assert!(preloaded_mappings(MAPS, "/etc/x.so", other_dev).is_empty());
    }

    #[test]
    fn only_executable_file_mappings_are_read() {
        let lines: Vec<_> = MAPS.lines().filter_map(exec_file_mapping).collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[1],
            ("/usr/lib/x86_64-linux-gnu/libc.so.6", libc::makedev(8, 1), 2222)
        );
        assert!(exec_file_mapping("7f00-7f10 r-xp 0 fe:0a 5 /a b/with space.so")
            .is_some_and(|(p, d, _)| p == "/a b/with space.so" && d == libc::makedev(0xfe, 0x0a)));
        assert!(exec_file_mapping("7f00-7f10 r-xp 0 08:01 0 /x").is_none());
        assert!(exec_file_mapping("7f00-7f10 r--p 0 08:01 5 /x").is_none());
        assert!(exec_file_mapping("7f00-7f10 r-xp 0 08:01 5 [vdso]").is_none());
    }

    /// F4: every attach type of every cgroup asked; the agent's own
    /// programs left out, the others named once each; a type the kernel
    /// refuses skipped.
    #[test]
    fn the_census_names_every_program_not_the_agent_s() {
        let targets = [
            ("/northnarrow.slice".to_string(), 10),
            ("/ (the root cgroup)".to_string(), 11),
        ];
        let query = |fd: i32, t: u32| -> std::io::Result<Vec<u32>> {
            match (fd, t) {
                (10, 1) => Ok(vec![77]),
                (11, 18) => Ok(vec![5, 78]),
                (11, 0) => Ok(vec![79, 79]),
                (_, 43) => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                _ => Ok(Vec::new()),
            }
        };
        let own: BTreeSet<u32> = [5].into_iter().collect();
        let hits = census_with(&targets, query, &own);
        let got: Vec<_> = hits
            .iter()
            .map(|h| (h.cgroup.as_str(), h.attach, h.prog_id))
            .collect();
        assert_eq!(
            got,
            [
                ("/ (the root cgroup)", "BPF_CGROUP_INET_INGRESS", 79),
                ("/ (the root cgroup)", "BPF_CGROUP_SYSCTL", 78),
                ("/northnarrow.slice", "BPF_CGROUP_INET_EGRESS", 77),
            ]
        );
        assert!(census_with(&targets, |_, _| Ok(vec![5]), &own).is_empty());
        let d = census_detail(&hits[2], Some("drop_all"));
        assert!(d.contains("id 77 `drop_all`") && d.contains("/northnarrow.slice"), "{d}");
        assert!(d.contains("not detached"), "{d}");
    }

    /// F4 (a): the rows that wake the census are the cgroup attaches.
    #[test]
    fn a_cgroup_attach_row_wakes_the_census() {
        use common::bpf_cmd::{BPF_LINK_CREATE, BPF_PROG_ATTACH};
        assert!(is_cgroup_attach_row(BPF_PROG_ATTACH, 1));
        assert!(is_cgroup_attach_row(BPF_LINK_CREATE, 6));
        assert!(!is_cgroup_attach_row(BPF_PROG_ATTACH, 5), "not a cgroup type");
        assert!(!is_cgroup_attach_row(0, 1), "not an attach");
    }

    /// A finding is signed once while it holds, its end once it is gone,
    /// and again once it came back; a kind not looked for this round keeps
    /// what was signed.
    #[test]
    fn a_finding_is_signed_once_while_it_holds() {
        let f = |d: &str| Finding {
            kind: CGROUP_FOREIGN_KIND,
            detail: d.to_string(),
        };
        let mut s = Signed::default();
        let a = [f("a"), f("b")];
        assert_eq!(s.fresh(&a, &[]).0.len(), 2);
        let (fresh, gone) = s.fresh(&a, &[]);
        assert!(fresh.is_empty() && gone.is_empty());
        // the census failed this round: nothing ends
        let (fresh, gone) = s.fresh(&[], &[CGROUP_FOREIGN_KIND]);
        assert!(fresh.is_empty() && gone.is_empty());
        let only_b = [f("b")];
        let (fresh, gone) = s.fresh(&only_b, &[]);
        assert!(fresh.is_empty());
        assert_eq!(gone.len(), 1);
        assert_eq!((gone[0].kind, gone[0].detail.as_str()), (CGROUP_FOREIGN_KIND, "a"));
        let back = [f("a"), f("b")];
        let (fresh, gone) = s.fresh(&back, &[]);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].detail, "a");
        assert!(gone.is_empty());
        let p = Finding {
            kind: PRELOAD_KIND,
            detail: "p".into(),
        };
        assert_eq!(s.fresh(std::slice::from_ref(&p), &[CGROUP_FOREIGN_KIND]).0.len(), 1);
        let (_, gone) = s.fresh(&[], &[CGROUP_FOREIGN_KIND]);
        assert_eq!(gone.len(), 1, "the preload ended; the census's kept");
        assert_eq!(gone[0].kind, PRELOAD_KIND);
    }
}
