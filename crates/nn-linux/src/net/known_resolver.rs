//! Lot 340 (the alpha's daily false positives): a DNS query's sender is a
//! known resolver, proven by its identity — not by its name.
//!
//! NN-L-NET-004/-005/-014 treat a resolver's queries as forwarded legs: the
//! verdict goes to the process that asked (traced back in the DNS cache) or
//! is a Log record, never a kill of the resolver; NN-L-NET-005 counts none
//! of its legs. That used to be granted by the basename of the sender's image
//! (`KNOWN_RESOLVER_PROGRAMS`): a tunnel run as `/tmp/x/dnsmasq` was never
//! killed, and CoreDNS, absent from the list, was judged on its pods' names
//! as its own. A sender is a known resolver now when the kernel says so:
//!
//! - **the host's resolver service**: its image's name is one of the list,
//!   the path lies in a root-owned system tree, and the image it runs is the
//!   host's file at that path — the same device and inode
//!   ([`AuthSessionTracker::runs_host_file`]), whatever mount namespace it
//!   runs in (systemd-resolved runs in its own). A copy, a container's file
//!   at that path, an image replaced since: not. The review of #552 (F4):
//!   and it runs as the system's service ([`system_service_in`]) — in its
//!   own unit's cgroup under `system.slice`, forked by PID 1 (or, dnsmasq,
//!   by the packaged NetworkManager), as a system user, with no dynamic
//!   loader variable in its environment. The packaged image run by a user
//!   or a webshell (a relay on another port, `LD_PRELOAD` with a tunnel in
//!   its constructor) is judged as any process;
//! - **the cluster's CoreDNS**: its image is `/coredns` (the official image's
//!   only program) in a container, and the container runtime's own record of
//!   that container — the OCI bundle's `config.json` that containerd, k3s'
//!   containerd or CRI-O write under `/run`, root's and writable by no one
//!   else — names a container `coredns` of the namespace `kube-system`,
//!   from a `coredns` image, running `/coredns`. A pod that ships a program
//!   at `/coredns` elsewhere than `kube-system` is not; who may create pods
//!   in `kube-system` holds the cluster. The review of #552 (F3): the
//!   container's id is the last segment of a `kubepods` cgroup path (never
//!   a user's delegated cgroup named with it), and the sender shares its PID
//!   and mount namespaces with the container's init, whose pid the runtime
//!   recorded in the bundle ([`ns_of_container`]).

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::decision::rules::net::sender_is_forwarder;
use crate::posture::lineage::{in_system_tree, AsOf, AuthSessionTracker};

/// The image CoreDNS runs in its container.
pub const COREDNS_IMAGE_PATH: &str = "/coredns";

/// The runtimes' bundle files of a container `<id>`, under the host's root:
/// containerd's and k3s' containerd's (`k8s.io` namespace), CRI-O's — the
/// directory, then the OCI spec, then the file the runtime records the
/// container's init pid in (the review of #552, F3: the shim's `init.pid`,
/// conmon's `pidfile`).
const BUNDLES: &[(&str, &str, &str)] = &[
    (
        "run/containerd/io.containerd.runtime.v2.task/k8s.io/",
        "/config.json",
        "/init.pid",
    ),
    (
        "run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/",
        "/config.json",
        "/init.pid",
    ),
    (
        "run/containers/storage/overlay-containers/",
        "/userdata/config.json",
        "/userdata/pidfile",
    ),
];

/// The first segment of a pod's cgroup path: the kubelet's root (the
/// systemd driver's slice, the cgroupfs driver's directory — k3s').
const KUBEPODS: &[&str] = &["kubepods.slice", "kubepods"];

/// The namespaces a sender shares with the container's init to be in it.
const CONTAINER_NS: &[&str] = &["pid", "mnt"];

/// A bundle file larger than this is not read.
const BUNDLE_MAX_BYTES: u64 = 1 << 20;

/// The review of #552 (F4): the units each packaged resolver runs as a
/// system service, by its image's name: its own (`kresd@1.service` by its
/// template's name), and for dnsmasq those of the network managers that
/// start one (NetworkManager, libvirt, LXC).
const RESOLVER_UNITS: &[(&str, &[&str])] = &[
    ("systemd-resolved", &["systemd-resolved"]),
    ("systemd-resolve", &["systemd-resolved"]),
    ("named", &["named", "bind9"]),
    ("unbound", &["unbound"]),
    (
        "dnsmasq",
        &[
            "dnsmasq",
            "NetworkManager",
            "libvirtd",
            "virtnetworkd",
            "lxc-net",
        ],
    ),
    ("dnscrypt-proxy", &["dnscrypt-proxy"]),
    ("pdns_recursor", &["pdns-recursor"]),
    ("kresd", &["kresd"]),
    ("stubby", &["stubby"]),
    ("connmand", &["connman"]),
];

/// The review of #552 (F4): the packaged program that may start dnsmasq
/// itself (its forker, not PID 1): NetworkManager's `dns=dnsmasq`.
const DNSMASQ_PARENT: &str = "/usr/sbin/NetworkManager";

/// The review of #552 (F4): the dynamic loader's variables, which run the
/// caller's code in any dynamically linked program.
const LOADER_VARS: &[&str] = &["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"];

/// The most of an environment read (a larger one is not proven clean).
const MAX_ENVIRON: u64 = 1 << 20;

/// The first uid a login user gets (`UID_MIN`); `nobody` is a system user.
const UID_MIN: u32 = 1000;
const NOBODY: u32 = 65534;

/// How long a proof is kept for its pid (read again after it), and how many
/// are kept.
const PROOF_TTL: Duration = Duration::from_secs(60);
const PROOF_CAP: usize = 64;

/// One proof: when it was read, the process's start (`/proc` ticks), the
/// image it was read for, the answer.
type Proof = (Instant, u64, String, bool);

/// The proofs of a resolver service or of CoreDNS read lately, by pid.
static RESOLVER_PROOFS: Mutex<Option<HashMap<u32, Proof>>> = Mutex::new(None);

/// The sender `pid`, whose image is `exe` (as the lineage named it at the
/// query), is a known resolver ([`self`]).
pub fn is_known_resolver(lineage: &AuthSessionTracker, pid: u32, exe: Option<&str>) -> bool {
    let proc = Path::new("/proc");
    known_resolver(
        lineage,
        pid,
        exe,
        &|exe| proven_on_host(pid, exe, || system_service_in(proc, lineage, pid, exe)),
        &|| {
            proven_on_host(pid, COREDNS_IMAGE_PATH, || {
                coredns_in(proc, Path::new("/"), pid)
            })
        },
    )
}

/// [`is_known_resolver`], the service's proof by `service` (for the image)
/// and CoreDNS's by `coredns`.
fn known_resolver(
    lineage: &AuthSessionTracker,
    pid: u32,
    exe: Option<&str>,
    service: &dyn Fn(&str) -> bool,
    coredns: &dyn Fn() -> bool,
) -> bool {
    let Some(exe) = exe else {
        return false;
    };
    if !sender_is_forwarder(Some(exe)) {
        return false;
    }
    if exe == COREDNS_IMAGE_PATH {
        return coredns();
    }
    in_system_tree(exe) && lineage.runs_host_file(pid, exe) && service(exe)
}

/// `prove` for the process `pid` running `exe` on this host, kept
/// [`PROOF_TTL`] for the same process and image.
fn proven_on_host(pid: u32, exe: &str, prove: impl FnOnce() -> bool) -> bool {
    let start = crate::state_read::read_state(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| start_ticks(&s));
    let Some(start) = start else {
        return false;
    };
    let now = Instant::now();
    {
        let g = RESOLVER_PROOFS.lock();
        if let Some((at, s, image, proven)) = g.as_ref().and_then(|m| m.get(&pid)) {
            if *s == start && image == exe && now.duration_since(*at) < PROOF_TTL {
                return *proven;
            }
        }
    }
    let proven = prove();
    let mut g = RESOLVER_PROOFS.lock();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= PROOF_CAP {
        m.retain(|_, (at, _, _, _)| now.duration_since(*at) < PROOF_TTL);
        if m.len() >= PROOF_CAP {
            m.clear();
        }
    }
    m.insert(pid, (now, start, exe.to_string(), proven));
    proven
}

/// Field 22 of a `/proc/<pid>/stat` text (the start, clock ticks).
fn start_ticks(stat: &str) -> Option<u64> {
    stat_field(stat, 19)
}

/// Field `n + 3` of a `/proc/<pid>/stat` text (`n` counted after `comm`).
fn stat_field(stat: &str, n: usize) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(n)?
        .parse()
        .ok()
}

/// The review of #552 (F4): the packaged resolver `exe` that `pid` runs
/// (`proc`: `/proc`) is the system's service — all of:
///
/// * its cgroup (the unified hierarchy's, `0::`) is one of its units
///   ([`RESOLVER_UNITS`]) right under `system.slice`: only root places a
///   process there, and a webshell runs in its web server's unit;
/// * PID 1 forked it — the kernel's fork record of its exec when the agent
///   saw it ([`AuthSessionTracker::fork_parent`]), else its parent now (a
///   daemon older than the agent, or one that forked itself away from the
///   exec: in its unit's cgroup either way) — or, for dnsmasq, the
///   packaged NetworkManager ([`DNSMASQ_PARENT`], by its image);
/// * every uid it runs as (real, effective, saved, filesystem) is a system
///   user's (below [`UID_MIN`], or `nobody`);
/// * its environment holds none of the dynamic loader's variables
///   ([`LOADER_VARS`]), read whole.
///
/// Anything unreadable is not proven. What this trusts: root's units (a
/// root that runs the packaged resolver with its own preload in a unit of
/// the resolver's name is not told apart) and the environment as the
/// process keeps it (a preloaded library may wipe it — only in a unit the
/// above already made root's).
pub fn system_service_in(proc: &Path, lineage: &AuthSessionTracker, pid: u32, exe: &str) -> bool {
    let dir = proc.join(pid.to_string());
    let base = exe.rsplit('/').next().unwrap_or(exe);
    let Some((_, units)) = RESOLVER_UNITS.iter().find(|(b, _)| *b == base) else {
        return false;
    };
    let Some(unit) = system_unit(&dir) else {
        return false;
    };
    if !units.contains(&unit.as_str()) {
        return false;
    }
    let parent = match lineage.fork_parent(pid, AsOf::Now) {
        Some(p) => p,
        None => match crate::state_read::read_state(dir.join("stat"))
            .ok()
            .and_then(|s| stat_field(&s, 1))
            .and_then(|p| u32::try_from(p).ok())
        {
            Some(p) => p,
            None => return false,
        },
    };
    let by_its_manager = base == "dnsmasq" && lineage.runs_host_file(parent, DNSMASQ_PARENT);
    if parent != 1 && !by_its_manager {
        return false;
    }
    system_user(&dir) && loader_free(&dir)
}

/// The system unit (`<name>.service`, its template's name for an instance)
/// the process `dir` (`/proc/<pid>`) runs in: its unified cgroup path is
/// `/system.slice/<unit>`, nothing below.
fn system_unit(dir: &Path) -> Option<String> {
    let cgroup = crate::state_read::read_state(dir.join("cgroup")).ok()?;
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let unit = path.strip_prefix("/system.slice/")?;
    if unit.contains('/') {
        return None;
    }
    let name = unit.strip_suffix(".service")?;
    let name = name.split_once('@').map_or(name, |(t, _)| t);
    (!name.is_empty()).then(|| name.to_string())
}

/// Every uid of the process `dir` (`Uid:` of its `status`) is a system
/// user's.
fn system_user(dir: &Path) -> bool {
    let Ok(status) = crate::state_read::read_state(dir.join("status")) else {
        return false;
    };
    let Some(uids) = status.lines().find_map(|l| l.strip_prefix("Uid:")) else {
        return false;
    };
    let uids: Vec<Option<u32>> = uids.split_whitespace().map(|u| u.parse().ok()).collect();
    uids.len() == 4
        && uids
            .iter()
            .all(|u| u.is_some_and(|u| u < UID_MIN || u == NOBODY))
}

/// The environment of the process `dir`, read whole, holds none of
/// [`LOADER_VARS`] (set, empty or not).
fn loader_free(dir: &Path) -> bool {
    let Ok(f) = std::fs::File::open(dir.join("environ")) else {
        return false;
    };
    let mut env = Vec::new();
    if f.take(MAX_ENVIRON + 1).read_to_end(&mut env).is_err() || env.len() as u64 > MAX_ENVIRON {
        return false;
    }
    !env.split(|b| *b == 0).any(|var| {
        LOADER_VARS.iter().any(|name| {
            var.strip_prefix(name.as_bytes())
                .is_some_and(|r| r.first() == Some(&b'='))
        })
    })
}

/// The process `pid` (`proc`: `/proc`) runs in a container its runtime
/// records (under the host's `root`) as the cluster's CoreDNS: the
/// container's id is the leaf of the sender's `kubepods` cgroup
/// ([`container_id`]), its bundle records CoreDNS, and the sender shares
/// its namespaces with the container's init ([`ns_of_container`]).
pub fn coredns_in(proc: &Path, root: &Path, pid: u32) -> bool {
    let Ok(cgroup) = crate::state_read::read_state(proc.join(pid.to_string()).join("cgroup"))
    else {
        return false;
    };
    let Some(id) = container_id(&cgroup) else {
        return false;
    };
    BUNDLES.iter().any(|(dir, spec, init)| {
        let dir = root.join(format!("{dir}{id}"));
        let spec = PathBuf::from(format!("{}{spec}", dir.display()));
        let init = PathBuf::from(format!("{}{init}", dir.display()));
        spec.exists() && bundle_is_coredns(&spec) && ns_of_container(proc, pid, &init)
    })
}

/// The container id a `/proc/<pid>/cgroup` text names — the review of #552
/// (F3): as the LAST segment of a pod's cgroup path, whose first segment is
/// the kubelet's root ([`KUBEPODS`]): a runtime's scope
/// (`cri-containerd-<id>.scope`, `crio-<id>.scope`, `docker-<id>.scope`) or
/// a bare 64-hex id (the cgroupfs driver: `/kubepods/burstable/pod<uid>/<id>`).
/// A user's delegated cgroup named with CoreDNS's id
/// (`/user.slice/…/app.slice/<id>`), an id elsewhere in a path, or lines
/// naming two ids: none.
fn container_id(cgroup: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for line in cgroup.lines() {
        let Some(path) = line.splitn(3, ':').nth(2) else {
            continue;
        };
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let (Some(first), Some(last)) = (segs.first(), segs.last()) else {
            continue;
        };
        if !KUBEPODS.contains(first) || segs.len() < 2 {
            continue;
        }
        let name = last.strip_suffix(".scope").unwrap_or(last);
        let id = ["cri-containerd-", "crio-", "docker-"]
            .iter()
            .find_map(|p| name.strip_prefix(p))
            .unwrap_or(name);
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        match &found {
            Some(f) if f != id => return None,
            _ => found = Some(id.to_string()),
        }
    }
    found
}

/// The review of #552 (F3): the sender `pid` (`proc`: `/proc`) shares its
/// PID and mount namespaces ([`CONTAINER_NS`]) with the container's init,
/// whose pid the runtime recorded at `init` (root's, writable by no one
/// else). Joining another process's namespaces takes `CAP_SYS_ADMIN` over
/// them: a user's process in a cgroup of its own has its own.
fn ns_of_container(proc: &Path, pid: u32, init: &Path) -> bool {
    let Some(init_pid) = owned_small_file(init)
        .and_then(|t| t.trim().parse::<u32>().ok())
        .filter(|p| *p > 1)
    else {
        return false;
    };
    let ns = |p: u32, kind: &str| {
        std::fs::read_link(proc.join(p.to_string()).join("ns").join(kind)).ok()
    };
    CONTAINER_NS
        .iter()
        .all(|kind| match (ns(pid, kind), ns(init_pid, kind)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        })
}

/// The text of the small file at `path` (a pid file), when it is a regular
/// file of the runtimes' owner writable by no one else.
fn owned_small_file(path: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(path).ok()?;
    if !m.is_file()
        || m.uid() != bundle_owner()
        || m.permissions().mode() & 0o022 != 0
        || m.len() > 64
    {
        return None;
    }
    std::fs::read(path)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The bundle at `path` is root's, writable by no one else, and records the
/// cluster's CoreDNS ([`spec_is_coredns`]).
fn bundle_is_coredns(path: &Path) -> bool {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !m.is_file()
        || m.uid() != bundle_owner()
        || m.permissions().mode() & 0o022 != 0
        || m.len() > BUNDLE_MAX_BYTES
    {
        return false;
    }
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|spec| spec_is_coredns(&spec))
}

/// The owner a runtime's bundle must have: root (tests: the user running
/// them, the fixtures' owner).
#[cfg(not(test))]
fn bundle_owner() -> u32 {
    0
}

#[cfg(test)]
fn bundle_owner() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// An OCI runtime spec records the cluster's CoreDNS: its annotations name
/// the container `coredns` in the namespace `kube-system` from a `coredns`
/// image (the repository's last part: `coredns/coredns`,
/// `rancher/mirrored-coredns-coredns`), and its process runs `/coredns`. The
/// CRI annotations of containerd (`io.kubernetes.cri.*`) and CRI-O
/// (`io.kubernetes.container.name`, `io.kubernetes.pod.namespace`,
/// `io.kubernetes.cri-o.ImageName`).
pub fn spec_is_coredns(spec: &serde_json::Value) -> bool {
    let a = &spec["annotations"];
    let first = |keys: &[&str]| keys.iter().find_map(|k| a[*k].as_str());
    let namespace = first(&[
        "io.kubernetes.cri.sandbox-namespace",
        "io.kubernetes.pod.namespace",
    ]);
    let name = first(&[
        "io.kubernetes.cri.container-name",
        "io.kubernetes.container.name",
    ]);
    let image = first(&[
        "io.kubernetes.cri.image-name",
        "io.kubernetes.cri-o.ImageName",
    ]);
    let program = spec["process"]["args"][0].as_str();
    namespace == Some("kube-system")
        && name == Some("coredns")
        && image.is_some_and(is_coredns_image)
        && program == Some(COREDNS_IMAGE_PATH)
}

/// An image reference whose repository's last part is CoreDNS's
/// (`registry.k8s.io/coredns/coredns:v1.11.1`,
/// `docker.io/rancher/mirrored-coredns-coredns:1.10.1`, `…@sha256:…`).
fn is_coredns_image(image: &str) -> bool {
    let repo = image.split('@').next().unwrap_or(image);
    let last = repo.rsplit('/').next().unwrap_or(repo);
    let name = last.split(':').next().unwrap_or(last);
    // `coredns`, or a mirror's `<prefix>-coredns`
    name.rsplit('-').next() == Some("coredns")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn spec(ns: &str, name: &str, image: &str, program: &str) -> String {
        format!(
            r#"{{"ociVersion":"1.1.0","process":{{"args":["{program}","-conf","/etc/coredns/Corefile"]}},
            "annotations":{{"io.kubernetes.cri.container-type":"container",
            "io.kubernetes.cri.sandbox-namespace":"{ns}","io.kubernetes.cri.container-name":"{name}",
            "io.kubernetes.cri.image-name":"{image}"}}}}"#
        )
    }

    /// A fixture: `/proc/<pid>/cgroup` naming the container, and its bundle
    /// written by a runtime (mode `mode`). The review of #552 (F3): the
    /// sender is the container's init — the runtime's `init.pid` names it,
    /// and its namespaces are the init's ([`namespaces`]).
    fn fixture(t: &Path, pid: u32, cgroup: &str, bundle_dir: &str, body: &str, mode: u32) {
        let p = t.join("proc").join(pid.to_string());
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("cgroup"), cgroup).unwrap();
        namespaces(t, pid, "4026532901");
        let b = t.join(format!("{bundle_dir}{ID}"));
        std::fs::create_dir_all(&b).unwrap();
        let f = b.join("config.json");
        std::fs::write(&f, body).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        let i = b.join("init.pid");
        std::fs::write(&i, pid.to_string()).unwrap();
        std::fs::set_permissions(&i, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// `/proc/<pid>/ns/{pid,mnt}` of the fixture `t`, as links naming the
    /// namespaces `inode` (`pid:[<inode>]`).
    fn namespaces(t: &Path, pid: u32, inode: &str) {
        let ns = t.join("proc").join(pid.to_string()).join("ns");
        std::fs::create_dir_all(&ns).unwrap();
        for kind in CONTAINER_NS {
            let link = ns.join(kind);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("{kind}:[{inode}]"), &link).unwrap();
        }
    }

    /// Named test (the review of #552, F3; its probe
    /// `rev552_probe_coredns_id_in_a_users_delegated_cgroup` made a test): a
    /// local user's delegated cgroup named with CoreDNS's id (readable by
    /// anyone in `/proc/<coredns>/cgroup`), the real CoreDNS bundle in place,
    /// is no CoreDNS — it returned true. Nor is the id anywhere but the leaf
    /// of a `kubepods` path, nor a process in CoreDNS's cgroup whose
    /// namespaces are not the container init's, nor one whose runtime
    /// recorded no init or an init file another user may write.
    #[test]
    fn a_user_s_cgroup_named_with_coredns_s_id_is_no_coredns() {
        let ok = spec(
            "kube-system",
            "coredns",
            "docker.io/rancher/mirrored-coredns-coredns:1.10.1",
            "/coredns",
        );
        for cg in [
            format!("0::/user.slice/user-1000.slice/user@1000.service/app.slice/{ID}\n"),
            format!("0::/user.slice/user-1000.slice/user@1000.service/app.slice/kubepods/{ID}\n"),
            format!("0::/kubepods/burstable/pod1a2b/{ID}/x\n"),
            format!("0::/{ID}\n"),
            format!("0::/kubepods\n"),
            // two ids, the last one CoreDNS's
            format!(
                "12:pids:/kubepods/burstable/pod1/{}\n0::/kubepods/burstable/pod1/{ID}\n",
                "a".repeat(64)
            ),
        ] {
            let t = tempfile::tempdir().unwrap();
            fixture(t.path(), 4242, &cg, BUNDLES[0].0, &ok, 0o644);
            assert!(!coredns_in(&t.path().join("proc"), t.path(), 4242), "{cg}");
        }
        let cg = format!("0::/kubepods/burstable/pod1a2b-3c4d/{ID}\n");
        // in CoreDNS's cgroup, namespaces of its own (a user's `unshare`)
        let t = tempfile::tempdir().unwrap();
        fixture(t.path(), 4242, &cg, BUNDLES[1].0, &ok, 0o644);
        let init = t.path().join(format!("{}{ID}/init.pid", BUNDLES[1].0));
        std::fs::write(&init, "4300").unwrap();
        namespaces(t.path(), 4300, "4026532999");
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 4242),
            "own namespaces"
        );
        // its PID namespace the init's, its mount namespace its own
        namespaces(t.path(), 4300, "4026532901");
        let mnt = t.path().join("proc/4300/ns/mnt");
        std::fs::remove_file(&mnt).unwrap();
        std::os::unix::fs::symlink("mnt:[4026532999]", &mnt).unwrap();
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 4242),
            "its own mounts"
        );
        // ... and with the init's: CoreDNS (its worker, not the init)
        namespaces(t.path(), 4300, "4026532901");
        assert!(
            coredns_in(&t.path().join("proc"), t.path(), 4242),
            "the init's namespaces"
        );
        // an init file naming PID 1 (the host's init, whatever it shares)
        std::fs::write(&init, "1").unwrap();
        namespaces(t.path(), 1, "4026532901");
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 4242),
            "PID 1 as the init"
        );
        std::fs::write(&init, "4300").unwrap();
        // an init file another user may write, none at all, no init's entry
        std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 4242),
            "init.pid 0666"
        );
        std::fs::remove_file(&init).unwrap();
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 4242),
            "no init.pid"
        );
        std::fs::write(&init, "4301").unwrap();
        std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 4242),
            "no such init"
        );
    }

    /// Lot 340 (named): CoreDNS is proven by its runtime's record of the
    /// container — containerd's (systemd driver), k3s' containerd's
    /// (cgroupfs driver) — and nothing else is: another namespace, another
    /// container name, another image, another program, a bundle another user
    /// may write, no bundle, no container in the cgroup.
    #[test]
    fn coredns_is_proven_by_its_container_runtime_s_record() {
        let systemd = format!(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b.slice/cri-containerd-{ID}.scope\n"
        );
        let cgroupfs = format!("0::/kubepods/burstable/pod1a2b-3c4d/{ID}\n");
        let ok = spec(
            "kube-system",
            "coredns",
            "docker.io/rancher/mirrored-coredns-coredns:1.10.1",
            "/coredns",
        );
        for (cg, dir) in [(&systemd, BUNDLES[0].0), (&cgroupfs, BUNDLES[1].0)] {
            let t = tempfile::tempdir().unwrap();
            fixture(t.path(), 41, cg, dir, &ok, 0o644);
            assert!(coredns_in(&t.path().join("proc"), t.path(), 41), "{dir}");
        }
        for (body, mode) in [
            (
                spec("default", "coredns", "coredns/coredns:1.11.1", "/coredns"),
                0o644,
            ),
            (
                spec("kube-system", "exfil", "coredns/coredns:1.11.1", "/coredns"),
                0o644,
            ),
            (
                spec("kube-system", "coredns", "evil/dns:1", "/coredns"),
                0o644,
            ),
            (
                spec(
                    "kube-system",
                    "coredns",
                    "coredns/coredns:1.11.1",
                    "/bin/sh",
                ),
                0o644,
            ),
            (ok.clone(), 0o666),
            ("not json".to_string(), 0o644),
        ] {
            let t = tempfile::tempdir().unwrap();
            fixture(t.path(), 41, &systemd, BUNDLES[0].0, &body, mode);
            assert!(
                !coredns_in(&t.path().join("proc"), t.path(), 41),
                "{body} {mode:o}"
            );
        }
        let t = tempfile::tempdir().unwrap();
        fixture(
            t.path(),
            41,
            "0::/system.slice/coredns.service\n",
            BUNDLES[0].0,
            &ok,
            0o644,
        );
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 41),
            "no container"
        );
        assert!(
            !coredns_in(&t.path().join("proc"), t.path(), 42),
            "no process"
        );
    }

    #[test]
    fn coredns_images_are_told_by_their_repository() {
        for i in [
            "registry.k8s.io/coredns/coredns:v1.11.1",
            "docker.io/rancher/mirrored-coredns-coredns:1.10.1",
            "coredns/coredns@sha256:abcd",
            "coredns",
        ] {
            assert!(is_coredns_image(i), "{i}");
        }
        for i in [
            "evil/dns:1",
            "coredns/coredns-evil:1",
            "docker.io/x/notcoredns:1",
            "corednsx",
        ] {
            assert!(!is_coredns_image(i), "{i}");
        }
    }

    /// Lot 340 (named): a resolver at its packaged path is one by its image
    /// — the process runs the host's file there (here a copy of `sleep`
    /// placed at `usr/sbin/dnsmasq` of a fixture host root); the same
    /// program at a path outside a system tree, or named for another
    /// resolver whose file it does not run, is not.
    #[test]
    fn a_resolver_is_proven_by_the_host_file_it_runs() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("usr/sbin/dnsmasq");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::copy("/bin/sleep", &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        // the same file at a path outside a system tree, and at a system
        // path whose name is no resolver's
        for link in ["srv/x/dnsmasq", "usr/bin/curl"] {
            let at = t.path().join(link);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::hard_link(&bin, &at).unwrap();
        }
        let mut child = std::process::Command::new(&bin).arg("30").spawn().unwrap();
        let pid = child.id();
        let lineage = AuthSessionTracker::with_proc().with_host_root(t.path());
        // the review of #552 (F4): the process runs as dnsmasq's service —
        // its unit's cgroup, PID 1's child, a system user, no preload (a
        // fixture of its `/proc` entries: the test's own child is none)
        let svc = t.path().join("svc");
        service(
            &svc,
            pid,
            "/system.slice/dnsmasq.service",
            1,
            0,
            b"PATH=/usr/bin\0",
        );
        let is = |exe: &str| {
            known_resolver(
                &lineage,
                pid,
                Some(exe),
                &|exe| system_service_in(&svc, &lineage, pid, exe),
                &|| false,
            )
        };
        let proven = is("/usr/sbin/dnsmasq");
        // the same image, not run as dnsmasq's service (a user's session)
        let user = t.path().join("user");
        service(
            &user,
            pid,
            "/user.slice/user-1000.slice/session-2.scope",
            1,
            1000,
            b"\0",
        );
        let not_a_service = known_resolver(
            &lineage,
            pid,
            Some("/usr/sbin/dnsmasq"),
            &|exe| system_service_in(&user, &lineage, pid, exe),
            &|| true,
        );
        let outside = is("/srv/x/dnsmasq");
        let not_a_resolver = is("/usr/bin/curl");
        let other = is("/usr/sbin/unbound");
        let _ = child.kill();
        let _ = child.wait();
        assert!(proven, "the host's file at the resolver's path");
        assert!(!not_a_service, "the host's file, run by a user");
        assert!(!outside, "the same file outside a system tree");
        assert!(!not_a_resolver, "the same file under a name no resolver's");
        assert!(!other, "no file at /usr/sbin/unbound");
    }

    /// The `/proc/<pid>` entries of `proc` a service's proof reads: its
    /// unified cgroup `cgroup`, its parent `ppid`, every uid `uid`, its
    /// environment `env`.
    fn service(proc: &Path, pid: u32, cgroup: &str, ppid: u32, uid: u32, env: &[u8]) {
        let p = proc.join(pid.to_string());
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
        std::fs::write(
            p.join("stat"),
            format!(
                "{pid} (x y) S {ppid} {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 4242 0\n"
            ),
        )
        .unwrap();
        std::fs::write(
            p.join("status"),
            format!("Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t0\t0\t0\t0\n"),
        )
        .unwrap();
        std::fs::write(p.join("environ"), env).unwrap();
    }

    /// Named test (the review of #552, F4): a known resolver is the system's
    /// service, not the packaged image — systemd-resolved in its unit, PID
    /// 1's child, as its system user, is one; the same image run by a
    /// login user in a session, by a webshell in its web server's unit
    /// (`www-data`), with `LD_PRELOAD` (a tunnel in the constructor) or
    /// another loader variable, forked by a shell (the kernel's record of
    /// its exec, or its parent now), in a cgroup below its unit, under a
    /// unit not its own, with an environment that cannot be read: judged as
    /// any process.
    #[test]
    fn a_packaged_resolver_not_run_as_the_system_s_service_is_judged() {
        const RESOLVED: &str = "/usr/lib/systemd/systemd-resolved";
        const UNIT: &str = "/system.slice/systemd-resolved.service";
        const CLEAN: &[u8] = b"LANG=C.UTF-8\0PATH=/usr/bin\0";
        let t = tempfile::tempdir().unwrap();
        let proc = t.path().join("proc");
        let lineage = AuthSessionTracker::new(&proc);
        service(&proc, 50, UNIT, 1, 991, CLEAN);
        assert!(
            system_service_in(&proc, &lineage, 50, RESOLVED),
            "the service"
        );
        service(&proc, 51, "/system.slice/kresd@1.service", 1, 0, CLEAN);
        assert!(
            system_service_in(&proc, &lineage, 51, "/usr/sbin/kresd"),
            "an instance"
        );
        service(&proc, 52, "/system.slice/dnsmasq.service", 1, NOBODY, CLEAN);
        assert!(
            system_service_in(&proc, &lineage, 52, "/usr/sbin/dnsmasq"),
            "nobody"
        );
        let session = "/user.slice/user-1000.slice/session-3.scope";
        for (pid, cgroup, ppid, uid, env) in [
            (60, session, 1, 1000, CLEAN),
            (61, "/system.slice/php8.3-fpm.service", 1, 33, CLEAN),
            (62, UNIT, 1, 991, &b"LD_PRELOAD=/tmp/t.so\0"[..]),
            (63, UNIT, 1, 991, &b"PATH=/x\0LD_AUDIT=/tmp/a.so\0"[..]),
            (64, UNIT, 1, 991, &b"LD_LIBRARY_PATH=\0"[..]),
            (65, UNIT, 777, 991, CLEAN),
            (
                66,
                "/system.slice/systemd-resolved.service/x",
                1,
                991,
                CLEAN,
            ),
            (67, "/system.slice/unbound.service", 1, 991, CLEAN),
            (68, UNIT, 1, 1000, CLEAN),
            (69, "/init.scope", 1, 0, CLEAN),
        ] {
            service(&proc, pid, cgroup, ppid, uid, env);
            assert!(
                !system_service_in(&proc, &lineage, pid, RESOLVED),
                "pid {pid}"
            );
        }
        // a larger environment than is read, none readable
        service(
            &proc,
            70,
            UNIT,
            1,
            991,
            &vec![b'A'; (MAX_ENVIRON + 1) as usize],
        );
        service(&proc, 71, UNIT, 1, 991, CLEAN);
        std::fs::remove_file(proc.join("71/environ")).unwrap();
        for pid in [70, 71] {
            assert!(
                !system_service_in(&proc, &lineage, pid, RESOLVED),
                "pid {pid}"
            );
        }
        // the kernel's record of its exec: forked by a shell, though PID 1
        // is its parent now (a daemon that double-forked)
        service(&proc, 72, UNIT, 1, 991, CLEAN);
        lineage.ingest_spawn_event(&exec_forked_by(72, RESOLVED, 600));
        assert!(
            !system_service_in(&proc, &lineage, 72, RESOLVED),
            "forked by a shell"
        );
        service(&proc, 73, UNIT, 1, 991, CLEAN);
        lineage.ingest_spawn_event(&exec_forked_by(73, RESOLVED, 1));
        assert!(
            system_service_in(&proc, &lineage, 73, RESOLVED),
            "forked by PID 1"
        );
        // a name that is no resolver's
        assert!(!system_service_in(&proc, &lineage, 50, "/usr/bin/curl"));
    }

    /// Named test (the review of #552, F4): dnsmasq NetworkManager starts is
    /// its service — forked by the packaged NetworkManager (by its image),
    /// in NetworkManager's unit; the same under a parent that does not run
    /// the packaged NetworkManager, or another resolver under
    /// NetworkManager, is not.
    #[test]
    fn dnsmasq_is_a_service_under_the_packaged_network_manager_only() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let nm = root.join("usr/sbin/NetworkManager");
        std::fs::create_dir_all(nm.parent().unwrap()).unwrap();
        std::fs::write(&nm, b"nm").unwrap();
        std::fs::write(root.join("usr/sbin/other"), b"other").unwrap();
        let proc = t.path().join("proc");
        for (pid, image) in [(80, &nm), (81, &root.join("usr/sbin/other"))] {
            let p = proc.join(pid.to_string());
            std::fs::create_dir_all(&p).unwrap();
            std::os::unix::fs::symlink(image, p.join("exe")).unwrap();
        }
        let lineage = AuthSessionTracker::new(&proc).with_host_root(&root);
        let unit = "/system.slice/NetworkManager.service";
        service(&proc, 90, unit, 80, NOBODY, b"\0");
        assert!(system_service_in(&proc, &lineage, 90, "/usr/sbin/dnsmasq"));
        service(&proc, 91, unit, 81, NOBODY, b"\0");
        assert!(!system_service_in(&proc, &lineage, 91, "/usr/sbin/dnsmasq"));
        assert!(!system_service_in(&proc, &lineage, 90, "/usr/sbin/unbound"));
    }

    /// An exec of `exe` by `pid` whose fork the kernel recorded `forker`'s.
    fn exec_forked_by(pid: u32, exe: &str, forker: u32) -> nn_model::Event {
        nn_model::Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 991,
            gid: 991,
            comm: "x".into(),
            filename: exe.into(),
            timestamp_ns: 2_000_000_000,
            argv: vec![exe.into()],
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 1_000_000_000,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: exe.into(),
                fork_parent: forker,
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// Lot 340 (named): a sender named like a resolver is one only by its
    /// identity — not `/tmp/x/dnsmasq`, not a host path whose image is
    /// another file, not `/coredns` outside a recorded CoreDNS container;
    /// and never a sender whose name is no resolver's.
    #[test]
    fn a_resolver_by_name_only_is_not_a_known_resolver() {
        let t = tempfile::tempdir().unwrap();
        let lineage = AuthSessionTracker::new(t.path().join("proc"));
        for exe in [
            Some("/tmp/x/dnsmasq"),
            Some("/usr/sbin/dnsmasq"),
            Some("/usr/bin/curl"),
            Some("/coredns"),
            None,
        ] {
            assert!(!is_known_resolver(&lineage, 999_999, exe), "{exe:?}");
        }
    }
}
