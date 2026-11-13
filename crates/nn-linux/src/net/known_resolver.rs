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
//! - **the host's packaged resolver**: its image's name is one of the list,
//!   the path lies in a root-owned system tree, and the image it runs is the
//!   host's file at that path — the same device and inode
//!   ([`AuthSessionTracker::runs_host_file`]), whatever mount namespace it
//!   runs in (systemd-resolved runs in its own). A copy, a container's file
//!   at that path, an image replaced since: not;
//! - **the cluster's CoreDNS**: its image is `/coredns` (the official image's
//!   only program) in a container, and the container runtime's own record of
//!   that container — the OCI bundle's `config.json` that containerd, k3s'
//!   containerd or CRI-O write under `/run`, root's and writable by no one
//!   else — names a container `coredns` of the namespace `kube-system`,
//!   from a `coredns` image, running `/coredns`. A pod that ships a program
//!   at `/coredns` elsewhere than `kube-system` is not; who may create pods
//!   in `kube-system` holds the cluster.

use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::decision::rules::net::sender_is_forwarder;
use crate::posture::lineage::{in_system_tree, AuthSessionTracker};

/// The image CoreDNS runs in its container.
pub const COREDNS_IMAGE_PATH: &str = "/coredns";

/// The runtimes' bundle files of a container `<id>`, under the host's root:
/// containerd's and k3s' containerd's (`k8s.io` namespace), CRI-O's.
const BUNDLES: &[(&str, &str)] = &[
    (
        "run/containerd/io.containerd.runtime.v2.task/k8s.io/",
        "/config.json",
    ),
    (
        "run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/",
        "/config.json",
    ),
    (
        "run/containers/storage/overlay-containers/",
        "/userdata/config.json",
    ),
];

/// A bundle file larger than this is not read.
const BUNDLE_MAX_BYTES: u64 = 1 << 20;

/// How long a CoreDNS proof is kept for its pid (the bundle is read again
/// after it), and how many are kept.
const PROOF_TTL: Duration = Duration::from_secs(60);
const PROOF_CAP: usize = 64;

/// One proof of CoreDNS: when it was read, the process's start (`/proc`
/// ticks), the answer.
type Proof = (Instant, u64, bool);

/// The proofs of CoreDNS read lately, by pid.
static COREDNS_PROOFS: Mutex<Option<HashMap<u32, Proof>>> = Mutex::new(None);

/// The sender `pid`, whose image is `exe` (as the lineage named it at the
/// query), is a known resolver ([`self`]).
pub fn is_known_resolver(lineage: &AuthSessionTracker, pid: u32, exe: Option<&str>) -> bool {
    let Some(exe) = exe else {
        return false;
    };
    if !sender_is_forwarder(Some(exe)) {
        return false;
    }
    if exe == COREDNS_IMAGE_PATH {
        return coredns_on_host(pid);
    }
    in_system_tree(exe) && lineage.runs_host_file(pid, exe)
}

/// [`coredns_in`] on this host, kept [`PROOF_TTL`] for the same process.
fn coredns_on_host(pid: u32) -> bool {
    let start = crate::state_read::read_state(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| start_ticks(&s));
    let Some(start) = start else {
        return false;
    };
    let now = Instant::now();
    {
        let g = COREDNS_PROOFS.lock();
        if let Some((at, s, proven)) = g.as_ref().and_then(|m| m.get(&pid)) {
            if *s == start && now.duration_since(*at) < PROOF_TTL {
                return *proven;
            }
        }
    }
    let proven = coredns_in(Path::new("/proc"), Path::new("/"), pid);
    let mut g = COREDNS_PROOFS.lock();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= PROOF_CAP {
        m.retain(|_, (at, _, _)| now.duration_since(*at) < PROOF_TTL);
        if m.len() >= PROOF_CAP {
            m.clear();
        }
    }
    m.insert(pid, (now, start, proven));
    proven
}

/// Field 22 of a `/proc/<pid>/stat` text (the start, clock ticks).
fn start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// The process `pid` (`proc`: `/proc`) runs in a container its runtime
/// records (under the host's `root`) as the cluster's CoreDNS.
pub fn coredns_in(proc: &Path, root: &Path, pid: u32) -> bool {
    let Ok(cgroup) = crate::state_read::read_state(proc.join(pid.to_string()).join("cgroup"))
    else {
        return false;
    };
    container_ids(&cgroup)
        .iter()
        .any(|id| bundles(root, id).iter().any(|b| bundle_is_coredns(b)))
}

/// The 64-hex container ids a `/proc/<pid>/cgroup` text names: a runtime's
/// scope (`cri-containerd-<id>.scope`, `crio-<id>.scope`, `docker-<id>.scope`)
/// or a bare id (the cgroupfs driver: `/kubepods/burstable/pod<uid>/<id>`).
fn container_ids(cgroup: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in cgroup.lines() {
        let Some(path) = line.splitn(3, ':').nth(2) else {
            continue;
        };
        for seg in path.split('/') {
            let name = seg.strip_suffix(".scope").unwrap_or(seg);
            let id = ["cri-containerd-", "crio-", "docker-"]
                .iter()
                .find_map(|p| name.strip_prefix(p))
                .unwrap_or(name);
            if id.len() == 64
                && id.bytes().all(|b| b.is_ascii_hexdigit())
                && !ids.iter().any(|i| i == id)
            {
                ids.push(id.to_string());
            }
        }
    }
    ids
}

/// The bundle files of container `id` that exist under `root`.
fn bundles(root: &Path, id: &str) -> Vec<PathBuf> {
    BUNDLES
        .iter()
        .map(|(dir, file)| root.join(format!("{dir}{id}{file}")))
        .filter(|p| p.exists())
        .collect()
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
    /// written by a runtime (mode `mode`).
    fn fixture(t: &Path, pid: u32, cgroup: &str, bundle_dir: &str, body: &str, mode: u32) {
        let p = t.join("proc").join(pid.to_string());
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("cgroup"), cgroup).unwrap();
        let b = t.join(format!("{bundle_dir}{ID}"));
        std::fs::create_dir_all(&b).unwrap();
        let f = b.join("config.json");
        std::fs::write(&f, body).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
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
        let proven = is_known_resolver(&lineage, pid, Some("/usr/sbin/dnsmasq"));
        let outside = is_known_resolver(&lineage, pid, Some("/srv/x/dnsmasq"));
        let not_a_resolver = is_known_resolver(&lineage, pid, Some("/usr/bin/curl"));
        let other = is_known_resolver(&lineage, pid, Some("/usr/sbin/unbound"));
        let _ = child.kill();
        let _ = child.wait();
        assert!(proven, "the host's file at the resolver's path");
        assert!(!outside, "the same file outside a system tree");
        assert!(!not_a_resolver, "the same file under a name no resolver's");
        assert!(!other, "no file at /usr/sbin/unbound");
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
