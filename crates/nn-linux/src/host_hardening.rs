//! Host hardening checks — the kernel and boot-chain settings that decide
//! whether the agent's anti-tamper can be bypassed by a root that rewrites
//! the kernel at runtime (ROADMAP Tappa 10.8, external review of
//! 2026-10-10).
//!
//! The agent's BPF LSM hooks deny signals, ptrace and inode mutations to
//! root; they cannot deny a root that loads an unsigned module, `kexec`s
//! another kernel, or runs its own BPF programs against the agent's maps.
//! Those doors are closed by the host, not by the agent: kernel lockdown,
//! module signature enforcement, Secure Boot, `unprivileged_bpf_disabled`,
//! `kexec_load_disabled`, IMA measurement, a single bpffs mount.
//!
//! One implementation, three consumers: `nn-admin host-check` (table or
//! JSON), the agent at boot (one WARN per failing check) and
//! `install.sh` (prints the table after installing). Every check reads a
//! file under `/sys` or `/proc`, except the admin key, `nft` and the
//! install provenance (external audit DEP-007: how far `install.sh` could
//! verify the release); [`run_in`] takes a root prefix so tests build a
//! synthetic tree. Each check's id, status and value are signed in the
//! capability manifest at every boot (`host_hardening`).
//!
//! Lot 277: `lockdown=integrity` is the recommendation the table leads
//! with — without it root can rewrite the running kernel, the agent's
//! hooks with it, and no hook of the agent can refuse that; kexec counts
//! its load limits (6.6+); module signing counts `modules_disabled`; and
//! [`kernel_fixes`] compares the kernel's version with the fixes the
//! workers' sandbox and the anti-tamper rely on ([`KERNEL_FIXES`], each
//! version from the kernel's CVE records or the stable changelogs). A
//! distribution backports fixes without changing the version, so a kernel
//! whose version is below a fix is `unknown` on a distribution's kernel —
//! never `ok` — and `warn` only where the version is the upstream one.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The hardening is in place.
    Ok,
    /// Missing or weaker than recommended — the fix text says what to do.
    Warn,
    /// Cannot be determined on this host (no EFI, file absent) — informational.
    Unknown,
    /// Lot 377: the agent cannot run on this host as it is (its start
    /// refuses itself) — the fix text says what to change first.
    Fail,
}

/// One host hardening check.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Short stable identifier (`lockdown`, `secure_boot`, …).
    pub id: &'static str,
    /// What the check protects.
    pub name: &'static str,
    pub status: Status,
    /// What was observed (`[integrity]`, `0`, `mounted 1×`, …).
    pub value: String,
    /// How to fix it when `status` is `Warn` (empty otherwise).
    pub fix: &'static str,
}

/// Run every check against the live `/sys` and `/proc`.
pub fn run() -> Vec<Check> {
    run_in(Path::new("/"))
}

/// Run every check against a tree rooted at `root` (tests).
pub fn run_in(root: &Path) -> Vec<Check> {
    vec![
        bpf_lsm(root),
        lockdown(root),
        unprivileged_bpf(root),
        module_sig_enforce(root),
        secure_boot(root),
        ima(root),
        kexec_load_disabled(root),
        bpffs_mounts(root),
        admin_key(root),
        nft_tool(root),
        install_provenance(root),
        cgroup_v1(root),
        kernel_fixes(root),
        preload(root),
    ]
}

/// Lot 377: what to do about a preload list that loads a library.
pub const PRELOAD_FIX: &str = "remove the entry that names a library (or the file) — the agent and its watchdog check what their start maps and refuse to start with a library the release does not link (exit 78 and 16) — or run the agent on a host without one";

/// Lot 377: the dynamic loader's preload list (`/etc/ld.so.preload`) —
/// one that makes every program load a library is a host the agent cannot
/// run on (its start check, and the watchdog's, refuse it): `fail`, named;
/// one absent, empty or naming no file that exists is `ok`, and said. Read
/// as the loader reads it, by the rule the watchdog's respawn gate and
/// `install.sh`'s preflight share (`antitamper_bpf::preload`). Lot 385:
/// one naming a path this user could not look at (a directory it cannot
/// search) is `n/a`, `cannot check: run as root`.
fn preload(root: &Path) -> Check {
    use antitamper_bpf::preload::{judge_in, Verdict, PRELOAD_PATH};
    let (status, value) = match judge_in(root, Path::new(PRELOAD_PATH)) {
        Verdict::Absent => (Status::Ok, "absent".to_string()),
        Verdict::Inert { names: 0 } => (Status::Ok, "present, loads nothing (empty)".to_string()),
        Verdict::Inert { names } => (
            Status::Ok,
            format!("present, loads nothing ({names} name(s), no file any of them names exists)"),
        ),
        Verdict::Loads(files) => (
            Status::Fail,
            format!(
                "loads {} into every program: the agent and its watchdog refuse to start",
                files.join(", ")
            ),
        ),
        // lot 385 (the review of #593): a library this user could not look
        // at is no library absent — said like every check that could not
        // read, never `OK` (a denied one first: as root it is looked at)
        Verdict::Unseen(paths) => {
            let unread: Vec<Unread> = paths
                .iter()
                .map(|(p, kind)| Unread::of(&std::io::Error::from(*kind), p))
                .collect();
            let first = unread
                .iter()
                .find(|u| matches!(u, Unread::Denied(_)))
                .or(unread.first());
            let mut value = first.map(|u| u.said("")).unwrap_or_default();
            if unread.len() > 1 {
                value.push_str(&format!(
                    "; {} more path(s) the list names not looked at",
                    unread.len() - 1
                ));
            }
            (Status::Unknown, value)
        }
        Verdict::Unjudged(why) => (
            Status::Fail,
            format!("cannot be judged ({why}); every program reads it at its start"),
        ),
    };
    Check {
        id: "preload",
        name: "Library preload list",
        status,
        value,
        fix: PRELOAD_FIX,
    }
}

/// Lot 277: a kernel fix the workers' sandbox or the anti-tamper relies
/// on, by the first release of each stable branch that carries it.
#[derive(Debug, Clone, Copy)]
pub struct KernelFix {
    pub cve: &'static str,
    /// What the bug gives an attacker against the agent.
    pub what: &'static str,
    /// The first release with the bug: older kernels are not affected.
    pub introduced: (u32, u32, u32),
    /// `(major, minor, sublevel)`: the first release of the `major.minor`
    /// stable branch with the fix.
    pub stable: &'static [(u32, u32, u32)],
    /// The first mainline release with the fix (`major.minor`, every
    /// later branch has it).
    pub mainline: (u32, u32),
    /// Where the versions come from.
    pub source: &'static str,
}

/// Lot 277: the fixes [`kernel_fixes`] checks, as published (read on
/// 2026-11-03):
///
/// - CVE-2022-0847 (Dirty Pipe): a page-cache write to any file the caller
///   can read — the agent's binaries, its configuration. Since 5.8 (commit
///   f6dd975583bd); fixed in 5.10.102, 5.15.25, 5.16.11 and mainline 5.17
///   (commit 9d2231c5d74e): <https://dirtypipe.cm4all.com/> and
///   `ChangeLog-5.10.102`, `-5.15.25`, `-5.16.11`, `-5.17` on
///   cdn.kernel.org.
/// - CVE-2022-30594: `PTRACE_SEIZE` sets `PTRACE_O_SUSPEND_SECCOMP`
///   without the capability — a tracer suspends a seccomp filter. Since
///   4.3 (commit 13c4a90119d2); fixed in 4.19.238, 5.4.189, 5.10.110,
///   5.15.33, 5.16.19, 5.17.2 and mainline 5.18 (commit ee1fee900537): the
///   CVE record ("before 5.17.2"), `ChangeLog-4.19.238`, `-5.4.189`,
///   `-5.10.110`, `-5.15.33`, `-5.16.19`, `-5.17.2`, `-5.18` (the review of
///   #494, D3: the 4.19 and 5.4 branches).
/// - CVE-2024-42318: `keyctl(KEYCTL_SESSION_TO_PARENT)` drops the caller's
///   Landlock domain (`cred_transfer`). Since 5.13; fixed in 5.15.165,
///   6.1.103, 6.6.44, 6.10.3 and mainline 6.11: the kernel CNA's record,
///   `vulns.git` `cve/published/2024/CVE-2024-42318.json`.
/// - CVE-2025-68736: rights reached through a disconnected directory of a
///   bind mount. Since 5.13; fixed in 6.1.189, 6.6.143, 6.12.80, 6.18.2
///   and mainline 6.19 — no 5.15 fix listed: the kernel CNA's record,
///   `vulns.git` `cve/published/2025/CVE-2025-68736.json`.
pub const KERNEL_FIXES: &[KernelFix] = &[
    KernelFix {
        cve: "CVE-2022-0847",
        what: "Dirty Pipe: a write into the page cache of any readable file (the agent's binaries)",
        introduced: (5, 8, 0),
        stable: &[(5, 10, 102), (5, 15, 25), (5, 16, 11)],
        mainline: (5, 17),
        source: "https://dirtypipe.cm4all.com/ ; cdn.kernel.org ChangeLog-5.10.102, -5.15.25, -5.16.11, -5.17",
    },
    KernelFix {
        cve: "CVE-2022-30594",
        what: "PTRACE_SEIZE suspends a seccomp filter (the workers' last layer)",
        introduced: (4, 3, 0),
        stable: &[
            (4, 19, 238),
            (5, 4, 189),
            (5, 10, 110),
            (5, 15, 33),
            (5, 16, 19),
            (5, 17, 2),
        ],
        mainline: (5, 18),
        source: "https://www.cve.org/CVERecord?id=CVE-2022-30594 ; cdn.kernel.org ChangeLog-4.19.238, -5.4.189, -5.10.110, -5.15.33, -5.16.19, -5.17.2, -5.18",
    },
    KernelFix {
        cve: "CVE-2024-42318",
        what: "keyctl(KEYCTL_SESSION_TO_PARENT) drops a Landlock domain (the workers' filter refuses keyctl)",
        introduced: (5, 13, 0),
        stable: &[(5, 15, 165), (6, 1, 103), (6, 6, 44), (6, 10, 3)],
        mainline: (6, 11),
        source: "https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2024/CVE-2024-42318.json",
    },
    KernelFix {
        cve: "CVE-2025-68736",
        what: "Landlock rights through a disconnected directory (the workers hold no filesystem right)",
        introduced: (5, 13, 0),
        stable: &[(6, 1, 189), (6, 6, 143), (6, 12, 80), (6, 18, 2)],
        mainline: (6, 19),
        source: "https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2025/CVE-2025-68736.json",
    },
];

/// Lot 277: what a kernel's version says of one fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixState {
    /// Older than the bug.
    NotAffected,
    /// The version carries the fix (its stable branch's, or mainline's).
    Fixed,
    /// The upstream version below the fix, on a kernel whose version is
    /// the upstream one.
    Missing,
    /// The version below the fix on a distribution's kernel, which may
    /// carry it backported: not known.
    Unknown,
}

/// Lot 277: the running kernel's upstream version and whether a
/// distribution's backports may make the number lag its fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVersion {
    pub version: (u32, u32, u32),
    /// `osrelease`, and where the upstream version was read when not from
    /// it (`Ubuntu … 5.15.131`, `Debian 6.1.112-1`).
    pub release: String,
    /// The distribution that built it, when its files say so.
    pub distro: Option<&'static str>,
}

/// `major.minor[.sublevel]` at the start of `s`.
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let head: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut it = head.split('.').filter(|p| !p.is_empty());
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let sub = it.next().map_or(Some(0), |p| p.parse().ok())?;
    Some((major, minor, sub))
}

/// Lot 277: the kernel's upstream version — Ubuntu's
/// `/proc/version_signature` (its last field is the upstream stable
/// version the kernel is based on), Debian's `Debian <version>` in
/// `/proc/version` (the one of the kernel's own branch, not the
/// compiler's), else `osrelease`. A distribution is named when its files
/// say so, or when `osrelease` keeps a sublevel of 0 behind a suffix (the
/// enterprise kernels' frozen numbers: `5.14.0-427.el9`).
pub fn kernel_version(root: &Path) -> Option<KernelVersion> {
    let osrelease = read(root, "/proc/sys/kernel/osrelease")?;
    let own = parse_version(&osrelease)?;
    if let Some(sig) = read(root, "/proc/version_signature") {
        if let Some(v) = sig.split_whitespace().last().and_then(parse_version) {
            if (v.0, v.1) == (own.0, own.1) {
                return Some(KernelVersion {
                    version: v,
                    release: format!("{osrelease} ({sig})"),
                    distro: Some("Ubuntu"),
                });
            }
        }
    }
    if let Some(banner) = read(root, "/proc/version") {
        let debian = banner
            .match_indices("Debian ")
            .filter_map(|(i, _)| {
                let rest = &banner[i + "Debian ".len()..];
                let v = parse_version(rest)?;
                ((v.0, v.1) == (own.0, own.1)).then(|| {
                    let word = rest.split_whitespace().next().unwrap_or_default();
                    (v, word.to_string())
                })
            })
            .last();
        if let Some((v, word)) = debian {
            return Some(KernelVersion {
                version: v,
                release: format!("{osrelease} (Debian {word})"),
                distro: Some("Debian"),
            });
        }
    }
    let suffix = osrelease
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_string();
    let lower = osrelease.to_ascii_lowercase();
    let distro = if lower.contains(".el") {
        Some("Red Hat family")
    } else if lower.contains("-default") || lower.contains("suse") {
        Some("SUSE")
    } else if lower.contains("ubuntu") || lower.contains("-generic") {
        Some("Ubuntu")
    } else if own.2 == 0 && !suffix.is_empty() && !suffix.starts_with("-rc") {
        Some("a distribution")
    } else {
        None
    };
    Some(KernelVersion {
        version: own,
        release: osrelease,
        distro,
    })
}

/// Lot 277: what `v` says of `fix`.
pub fn fix_state(fix: &KernelFix, v: &KernelVersion) -> FixState {
    let (major, minor, sub) = v.version;
    if (major, minor, sub) < fix.introduced {
        return FixState::NotAffected;
    }
    if (major, minor) >= fix.mainline {
        return FixState::Fixed;
    }
    let in_branch = fix
        .stable
        .iter()
        .find(|(a, b, _)| (*a, *b) == (major, minor))
        .is_some_and(|(_, _, s)| sub >= *s);
    if in_branch {
        FixState::Fixed
    } else if v.distro.is_some() {
        FixState::Unknown
    } else {
        FixState::Missing
    }
}

/// Lot 277: the running kernel against [`KERNEL_FIXES`]. `ok` when every
/// fix is in the version (or the kernel predates the bug); `warn` when an
/// upstream kernel's version lacks one; else `unknown`: a distribution's
/// kernel whose version is below a fix may carry it backported — its
/// security tracker says, the version does not.
fn kernel_fixes(root: &Path) -> Check {
    let fix = "upgrade to a kernel whose stable branch carries the fix (docs/operator/KERNEL_COMPATIBILITY.md, \"Kernel fix level\"); on a distribution's kernel check its security tracker for each CVE named `unknown` — the agent's workers and anti-tamper rely on these fixes";
    let Some(v) = kernel_version(root) else {
        return Check {
            id: "kernel_fixes",
            name: "Kernel fixes the sandbox relies on",
            status: Status::Unknown,
            value: match read_as(root, "/proc/sys/kernel/osrelease") {
                Err(u) => u.said("osrelease absent"),
                Ok(_) => "osrelease unparsable".to_string(),
            },
            fix,
        };
    };
    let states: Vec<(&KernelFix, FixState)> =
        KERNEL_FIXES.iter().map(|f| (f, fix_state(f, &v))).collect();
    let status = if states.iter().any(|(_, s)| *s == FixState::Missing) {
        Status::Warn
    } else if states.iter().any(|(_, s)| *s == FixState::Unknown) {
        Status::Unknown
    } else {
        Status::Ok
    };
    let (a, b, c) = v.version;
    let parts: Vec<String> = states
        .iter()
        .map(|(f, s)| {
            let word = match s {
                FixState::NotAffected => "not affected",
                FixState::Fixed => "fixed",
                FixState::Missing => "MISSING",
                FixState::Unknown => "unknown",
            };
            format!("{} {word}", f.cve)
        })
        .collect();
    let backports = match (v.distro, status) {
        (Some(d), Status::Unknown) => {
            format!(" — {d} backports fixes without changing the version")
        }
        _ => String::new(),
    };
    Check {
        id: "kernel_fixes",
        name: "Kernel fixes the sandbox relies on",
        status,
        value: format!(
            "{a}.{b}.{c} from {}: {}{backports}",
            v.release,
            parts.join(", ")
        ),
        fix,
    }
}

/// The cgroup v1 controllers a root can mount on a host whose systemd runs
/// the unified hierarchy, and that stop or confine a process from outside
/// the v2 tree (lot 273b, the review of #489: the v1 `freezer` freezes the
/// agent where no v2 hook sees it).
const V1_CONTROLLERS: [&str; 5] = ["freezer", "devices", "net_cls", "net_prio", "perf_event"];

/// Lot 273b: which of [`V1_CONTROLLERS`] a root can mount as a cgroup v1
/// hierarchy — every one `/proc/cgroups` lists as enabled, unless the
/// kernel's command line has `cgroup_no_v1=all` or names it. Where systemd
/// runs the unified hierarchy the agent refuses writes to a v1 hierarchy
/// outside a trusted-installer window; the boot option refuses the mount
/// itself, before the agent is there.
fn cgroup_v1(root: &Path) -> Check {
    let cmdline = read(root, "/proc/cmdline").unwrap_or_default();
    let disabled: Vec<String> = cmdline
        .split_whitespace()
        .filter_map(|w| w.strip_prefix("cgroup_no_v1="))
        .flat_map(|v| v.split(',').map(str::to_string).collect::<Vec<_>>())
        .collect();
    let all = disabled.iter().any(|d| d == "all");
    let (status, value) = match read_as(root, "/proc/cgroups") {
        Err(u) => (Status::Unknown, u.said("/proc/cgroups absent")),
        Ok(table) => {
            let enabled: Vec<&str> = table
                .lines()
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() >= 4 && f[3] == "1").then(|| f[0])
                })
                .collect();
            let mountable: Vec<&str> = V1_CONTROLLERS
                .iter()
                .copied()
                .filter(|c| enabled.contains(c) && !all && !disabled.iter().any(|d| d == c))
                .collect();
            if mountable.is_empty() {
                (
                    Status::Ok,
                    if all {
                        "cgroup_no_v1=all".to_string()
                    } else {
                        "no v1 controller of these mountable".to_string()
                    },
                )
            } else {
                (
                    Status::Warn,
                    format!("mountable as cgroup v1: {}", mountable.join(", ")),
                )
            }
        }
    };
    Check {
        id: "cgroup_v1",
        name: "cgroup v1 controllers not mountable",
        status,
        value,
        fix: "on a host whose systemd runs the unified cgroup hierarchy, boot with `cgroup_no_v1=all` — a root can mount the v1 freezer, move the agent into it and freeze it (the agent refuses writes to a v1 hierarchy outside a trusted-installer window; the boot option refuses the mount itself)",
    }
}

/// External audit DEP-007: the install manifest `install.sh` writes,
/// relative to the root.
pub const INSTALL_MANIFEST_REL: &str = "etc/northnarrow/install-manifest.json";

/// External audit DEP-007: how far `install.sh` could verify the release
/// the installed binaries came from. Lab PR 220: only `attested` (the SLSA
/// attestation, bound to a release tag) says where they were built —
/// `checksums` (the tarball against an unsigned `SHA256SUMS`, swapped with
/// the tarball as easily) is a warning now, like `manifest` (the tree
/// vouching for itself) and `source-tree`, `unverified` and `package`, which
/// verified nothing on this host. Lot 354: `signed-checksums` (the tarball
/// against a `SHA256SUMS` whose `SHA256SUMS.asc` is a good signature by the
/// release key, on a host with no attestation verifier) is OK too: the key
/// lives only in the release's tag job. Accepted with a flag (a verifier ran
/// and refused), it is a warning. The agent boots at every level (a
/// lab or a developer host must keep working), so the level is reported
/// here.
fn install_provenance(root: &Path) -> Check {
    let path = root.join(INSTALL_MANIFEST_REL);
    let (status, value) = match antitamper_bpf::kernel_roots::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            Status::Unknown,
            "no install manifest (not installed by install.sh or a package)".to_string(),
        ),
        Err(e) => (Status::Warn, format!("install manifest unreadable: {e}")),
        Ok(text) => match serde_json::from_str::<crate::install_manifest::InstallManifest>(&text) {
            Err(e) => (Status::Warn, format!("install manifest unparsable: {e}")),
            Ok(m) => {
                let status = match m.provenance.as_str() {
                    "attested" => Status::Ok,
                    "signed-checksums" if m.verify_override.is_none() => Status::Ok,
                    _ => Status::Warn,
                };
                let mut value = m.provenance.clone();
                if m.provenance == "package" {
                    value.push_str(" (origin not verified on this host)");
                }
                if let Some(flag) = m.verify_override.as_deref() {
                    value.push_str(&format!(" (accepted with {flag})"));
                }
                (status, value)
            }
        },
    };
    Check {
        id: "install_provenance",
        name: "release verified at install",
        status,
        value,
        fix: "install from the release tarball (next to the tree, or `--tarball`) with `SHA256SUMS` and `SHA256SUMS.asc` beside it (`signed-checksums`), or with `gh` or `cosign` for its tag-bound attestation (`attested`); install.sh refuses less without `--allow-unverified`: `checksums`, `manifest`, `source-tree`, `unverified` and `package` mean nothing proved where these binaries were built",
    }
}

/// The `install.sh` flag that accepts a host without `nft` (lab PR 165).
const WITHOUT_NFT_FLAG: &str = "--without-nftables";

/// A missing `nft` is a WARN like every other check: host-check has no
/// level above it, and its exit status (2) already marks the host. The
/// refusal belongs to the install paths: the packages depend on nftables
/// and `install.sh` refuses without it unless `--without-nftables`, which
/// is named here when the install manifest records it (lab PR 165).
///
/// External audit CMB-014: the per-process outbound block (a BlockOutbound
/// verdict, the COMBAT soft egress block of INVESTIGATE) is an nftables
/// rule: without `nft` the offender is not contained while the agent
/// analyses it. External audit ATP-014 (NN-AUD-262): the `nft` the agent
/// runs, found as it finds it ([`crate::trusted_bin`]: the system
/// directories, root's file) — one in `/usr/local` is not used any more.
/// Over a fixture tree the tree's owner stands for root.
fn nft_tool(root: &Path) -> Check {
    let found = crate::trusted_bin::Lookup::under(root).resolve("nft");
    let (status, value) = match found {
        Ok(bin) => (
            Status::Ok,
            format!(
                "/{}",
                bin.found()
                    .strip_prefix(root)
                    .unwrap_or(bin.found())
                    .display()
            ),
        ),
        Err(why) if !why.is_missing() => (Status::Warn, format!("not trusted: {why}")),
        Err(_) => {
            let accepted =
                antitamper_bpf::kernel_roots::read_to_string(root.join(INSTALL_MANIFEST_REL))
                    .ok()
                    .and_then(|t| {
                        serde_json::from_str::<crate::install_manifest::InstallManifest>(&t).ok()
                    })
                    .is_some_and(|m| {
                        m.prerequisite_overrides
                            .iter()
                            .any(|f| f == WITHOUT_NFT_FLAG)
                    });
            let mut value = "not installed".to_string();
            if accepted {
                value.push_str(&format!(" (accepted with {WITHOUT_NFT_FLAG})"));
            }
            (Status::Warn, value)
        }
    };
    Check {
        id: "nft",
        name: "nftables for COMBAT containment",
        status,
        value,
        fix: "install nftables (`apt-get install nftables` / `dnf install nftables`); the agent runs the `nft` of /usr/sbin, /usr/bin, /sbin or /bin only, root's and writable by nobody else — without `nft` neither a BlockOutbound verdict nor the COMBAT soft egress block drops the offender's traffic (the agent records a signed subsystem_degraded at boot, and each episode records the failure and shortens INVESTIGATE)",
    }
}

/// External audit DEP-001: where an admin PRIVATE key lands on the host —
/// the bootstrap key `install.sh` wrote before the fix and the one it writes
/// now (`--admin-key-out` default), relative to the root.
pub const ADMIN_KEY_PATHS: &[&str] = &["etc/northnarrow/admin.key", "root/northnarrow-admin.key"];

/// The admin private keys found at [`ADMIN_KEY_PATHS`] under `root`
/// (non-empty regular files), as absolute host paths.
pub fn admin_keys_on_host(root: &Path) -> Vec<String> {
    admin_key_probe(root).0
}

/// Lot 385 (the external tester's F9b-2): [`admin_keys_on_host`], and the
/// bootstrap paths this user could not look at (`/root` is root's: run
/// without root, the key there was "none" and the check said `OK`).
pub fn admin_key_probe(root: &Path) -> (Vec<String>, Vec<Unread>) {
    let mut found = Vec::new();
    let mut unread = Vec::new();
    for rel in ADMIN_KEY_PATHS {
        match antitamper_bpf::kernel_roots::metadata(root.join(rel)) {
            Ok(m) if m.is_file() && m.len() > 0 => found.push(format!("/{rel}")),
            Ok(_) => {}
            Err(e) => match Unread::of(&e, rel) {
                Unread::Absent => {}
                u => unread.push(u),
            },
        }
    }
    (found, unread)
}

/// Number of `Warn` checks in `checks`.
pub fn warn_count(checks: &[Check]) -> usize {
    checks.iter().filter(|c| c.status == Status::Warn).count()
}

/// Lot 377: number of `Fail` checks in `checks` (the agent cannot run on
/// this host as it is).
pub fn fail_count(checks: &[Check]) -> usize {
    checks.iter().filter(|c| c.status == Status::Fail).count()
}

/// Human table, one line per check.
pub fn render_table(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        let tag = match c.status {
            Status::Ok => "OK  ",
            Status::Warn => "WARN",
            Status::Unknown => "n/a ",
            Status::Fail => "FAIL",
        };
        out.push_str(&format!("{tag}  {:<32} {}\n", c.name, c.value));
        if matches!(c.status, Status::Warn | Status::Fail) && !c.fix.is_empty() {
            out.push_str(&format!("      fix: {}\n", c.fix));
        }
    }
    let warns = warn_count(checks);
    out.push_str(&format!(
        "{} check(s), {warns} warning(s){}\n",
        checks.len(),
        if warns > 0 {
            " — the agent's anti-tamper holds only while root cannot rewrite the kernel at runtime"
        } else {
            ""
        }
    ));
    // Lot 385 (F9b-2): checks this user could not read, said apart — the
    // count above holds no verdict about them
    let unread = checks
        .iter()
        .filter(|c| c.value.starts_with(CANNOT_CHECK))
        .count();
    if unread > 0 {
        out.push_str(&format!(
            "{unread} check(s) could not be read as this user — run it as root: `sudo nn-admin host-check`\n"
        ));
    }
    // Lot 377: a host the agent cannot run on, said apart from the hardening
    let fails = fail_count(checks);
    if fails > 0 {
        out.push_str(&format!(
            "{fails} failure(s) — the agent does not start on this host until each FAIL is fixed\n"
        ));
    }
    out
}

fn read(root: &Path, rel: &str) -> Option<String> {
    read_as(root, rel).ok()
}

/// Lot 385 (the external tester's F9b-2): why a host file gave no value.
/// `nn-admin host-check` run without root cannot read some of them (the
/// admin key under `/root`, IMA's securityfs files): a check that could not
/// look says so, never `OK` nor "not present".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// The file is not there.
    Absent,
    /// The file is there and this user may not read it (`EACCES`, `EPERM`).
    Denied(String),
    /// Another error.
    Failed(String),
}

/// The value of a check that could not read its file as this user.
pub const CANNOT_CHECK: &str = "cannot check: run as root";

impl Unread {
    fn of(e: &std::io::Error, rel: &str) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Unread::Absent,
            std::io::ErrorKind::PermissionDenied => {
                Unread::Denied(format!("/{}", rel.trim_start_matches('/')))
            }
            _ => Unread::Failed(format!("/{}: {e}", rel.trim_start_matches('/'))),
        }
    }

    /// What the check shows: `absent` when the file is not there, else why
    /// it could not be read.
    pub fn said(&self, absent: &str) -> String {
        match self {
            Unread::Absent => absent.to_string(),
            Unread::Denied(path) => format!("{CANNOT_CHECK} ({path} is not readable as this user)"),
            Unread::Failed(why) => format!("cannot check: {why}"),
        }
    }
}

/// The trimmed text of `rel` under `root`, or why there is none.
fn read_as(root: &Path, rel: &str) -> Result<String, Unread> {
    let p: PathBuf = root.join(rel.trim_start_matches('/'));
    crate::state_read::read_state(p)
        .map(|s| s.trim().to_string())
        .map_err(|e| Unread::of(&e, rel))
}

fn bpf_lsm(root: &Path) -> Check {
    let (status, value) = match read_as(root, "/sys/kernel/security/lsm") {
        Ok(list) if list.split(',').any(|l| l == "bpf") => (Status::Ok, list),
        Ok(list) => (Status::Warn, list),
        Err(u) => (Status::Unknown, u.said("securityfs not readable")),
    };
    Check {
        id: "bpf_lsm",
        name: "BPF LSM in the active LSM list",
        status,
        value,
        fix: "append `bpf` to the LSM list the kernel runs (never a fixed `lsm=` list: it can switch SELinux or AppArmor off; docs/operator/KERNEL_COMPATIBILITY.md, \"Enabling the bpf LSM\") and reboot",
    }
}

/// The lockdown check's fix when the mode is none.
const LOCKDOWN_FIX: &str = "boot with `lockdown=integrity` (Secure Boot enables it on most distros) — recommended on every host the agent defends: without it root can rewrite the running kernel (an unsigned module, /dev/mem, kexec of an unsigned kernel, a kprobe's write) and remove the agent's hooks with it, which no hook of the agent can refuse";

/// Lot 280b: the lockdown check's fix when the mode is confidentiality.
const LOCKDOWN_CONFIDENTIALITY_FIX: &str = "boot with `lockdown=integrity` instead of `confidentiality`: confidentiality takes from every BPF program loaded after it the helpers that read kernel memory (bpf_probe_read_kernel and its kin) and refuses new kprobes, so the agent's next start (an upgrade, a restart) loads without the sensors and deny hooks that use them (docs/operator/KERNEL_COMPATIBILITY.md, \"Lockdown\"); integrity keeps every protection against rewriting the kernel";

fn lockdown(root: &Path) -> Check {
    let (status, value, fix) = match read_as(root, "/sys/kernel/security/lockdown") {
        // Lot 280b: confidentiality blinds the agent's next start
        Ok(s) if s.contains("[confidentiality]") => (Status::Warn, s, LOCKDOWN_CONFIDENTIALITY_FIX),
        Ok(s) if s.contains("[integrity]") => (Status::Ok, s, LOCKDOWN_FIX),
        Ok(s) => (Status::Warn, s, LOCKDOWN_FIX),
        Err(u) => (
            Status::Unknown,
            u.said("lockdown LSM not present"),
            LOCKDOWN_FIX,
        ),
    };
    Check {
        id: "lockdown",
        name: "Kernel lockdown mode",
        status,
        value,
        fix,
    }
}

fn unprivileged_bpf(root: &Path) -> Check {
    let (status, value) = match read_as(root, "/proc/sys/kernel/unprivileged_bpf_disabled") {
        Ok(v) if v == "1" || v == "2" => (Status::Ok, v),
        Ok(v) => (Status::Warn, v),
        Err(u) => (Status::Unknown, u.said("sysctl absent")),
    };
    Check {
        id: "unprivileged_bpf",
        name: "Unprivileged BPF disabled",
        status,
        value,
        fix: "`sysctl -w kernel.unprivileged_bpf_disabled=1` (persist in /etc/sysctl.d/) — only CAP_BPF/CAP_SYS_ADMIN may load BPF programs",
    }
}

fn module_sig_enforce(root: &Path) -> Check {
    // Lockdown in integrity (or confidentiality) mode refuses an unsigned
    // module whatever `sig_enforce` says (LOCKDOWN_MODULE_SIGNATURE) —
    // checked on Ubuntu 22.04 with sig_enforce=N: "Lockdown: unsigned
    // module loading is restricted".
    let lockdown_mode = read(root, "/sys/kernel/security/lockdown").and_then(|s| {
        if s.contains("[integrity]") {
            Some("integrity")
        } else if s.contains("[confidentiality]") {
            Some("confidentiality")
        } else {
            None
        }
    });
    // Lot 277: `kernel.modules_disabled=1` (one-way until reboot) refuses
    // every module load, signed or not.
    let modules_off = read(root, "/proc/sys/kernel/modules_disabled").as_deref() == Some("1");
    let (status, value) = match read_as(root, "/sys/module/module/parameters/sig_enforce") {
        Ok(v) if v == "Y" => (Status::Ok, v),
        Ok(v) if modules_off => (
            Status::Ok,
            format!("{v} (every module load refused: modules_disabled=1)"),
        ),
        Ok(v) => match lockdown_mode {
            Some(mode) => (
                Status::Ok,
                format!("{v} (unsigned modules refused by lockdown={mode})"),
            ),
            None => (Status::Warn, v),
        },
        Err(u) => (
            Status::Unknown,
            u.said("parameter absent (CONFIG_MODULE_SIG off?)"),
        ),
    };
    Check {
        id: "module_sig_enforce",
        name: "Kernel module signature enforced",
        status,
        value,
        fix: "boot with `module.sig_enforce=1` (or Secure Boot + lockdown, which forces it): an unsigned module is the classic way to blind a kernel sensor",
    }
}

fn secure_boot(root: &Path) -> Check {
    let p = root.join("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    let (status, value) = match antitamper_bpf::kernel_roots::read_all(&p) {
        Ok(bytes) if bytes.len() >= 5 && bytes[4] == 1 => (Status::Ok, "enabled".to_string()),
        Ok(bytes) if bytes.len() >= 5 => (Status::Warn, "disabled".to_string()),
        Ok(_) => (Status::Unknown, "efivar unreadable".to_string()),
        Err(e) => (
            Status::Unknown,
            Unread::of(
                &e,
                "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            )
            .said("no EFI variable (legacy BIOS or VM without UEFI)"),
        ),
    };
    Check {
        id: "secure_boot",
        name: "UEFI Secure Boot",
        status,
        value,
        fix: "enable Secure Boot in firmware with the distro's shim (or your own keys): anchors the boot chain and turns on lockdown + module signing",
    }
}

fn ima(root: &Path) -> Check {
    // either place; a file that is there but not readable is said, never
    // "not present" (lot 385: securityfs's ima/ is root's)
    let count =
        read_as(root, "/sys/kernel/security/ima/runtime_measurements_count").or_else(|first| {
            read_as(
                root,
                "/sys/kernel/security/integrity/ima/runtime_measurements_count",
            )
            .map_err(|second| {
                if first == Unread::Absent {
                    second
                } else {
                    first
                }
            })
        });
    let (status, value) = match count {
        Ok(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 => (Status::Ok, format!("{n} measurements")),
            _ => (Status::Warn, format!("{v} measurements (no policy loaded)")),
        },
        Err(u) => (Status::Unknown, u.said("IMA not present in this kernel")),
    };
    Check {
        id: "ima",
        name: "IMA measurement / appraisal active",
        status,
        value,
        fix: "boot with `ima_policy=tcb` (measure) or an appraise policy with signed binaries: makes a replaced agent binary fail before it runs",
    }
}

fn kexec_load_disabled(root: &Path) -> Check {
    // Lot 277: on 6.6+ the load limits — both 0 refuse every load as the
    // switch does.
    let limit = |rel: &str| read(root, rel);
    let limits_zero = limit("/proc/sys/kernel/kexec_load_limit_reboot").as_deref() == Some("0")
        && limit("/proc/sys/kernel/kexec_load_limit_panic").as_deref() == Some("0");
    let lockdown_on = read(root, "/sys/kernel/security/lockdown")
        .is_some_and(|s| s.contains("[integrity]") || s.contains("[confidentiality]"));
    let (status, value) = match read_as(root, "/proc/sys/kernel/kexec_load_disabled") {
        Ok(v) if v == "1" => (Status::Ok, v),
        Ok(v) if limits_zero => (
            Status::Ok,
            format!("{v} (kexec_load_limit_reboot and _panic 0: no load left)"),
        ),
        Ok(v) if lockdown_on => (
            Status::Warn,
            format!(
                "{v} (lockdown refuses an unsigned image; a signed kernel still boots with \
                 another command line)"
            ),
        ),
        Ok(v) => (Status::Warn, v),
        Err(u) => (Status::Unknown, u.said("sysctl absent (CONFIG_KEXEC off)")),
    };
    Check {
        id: "kexec_load_disabled",
        name: "kexec disabled",
        status,
        value,
        fix: "`sysctl -w kernel.kexec_load_disabled=1` (one-way until reboot; persist in /etc/sysctl.d/) — kexec boots a different kernel without a reboot the sensor would notice",
    }
}

/// Lot 365: the mount ids of the agent's pin lock in the mount table `text`
/// — the lock `pin_lock::state_in` finds in place (the self-bind of
/// `pin_root`, private and unbindable, the child of the whole bpffs at
/// /sys/fs/bpf) and each lock stacked on it that is private and
/// unbindable too. None when the lock is not in place.
fn own_pin_lock(text: &[u8], pin_root: &Path) -> Vec<u64> {
    use crate::anti_tamper::pin_lock::{is_lock, propagation_is_locked, state_in, State};
    let State::InPlace(first) = state_in(text, pin_root) else {
        return Vec::new();
    };
    let t = crate::mountinfo::parse(text).entries;
    let attrs = crate::mount_attrs::attrs_of(text);
    let mut ids = vec![first];
    while let Some(over) = t.iter().find(|m| {
        m.parent == ids[ids.len() - 1] && m.mount_point == pin_root && !ids.contains(&m.id)
    }) {
        let locked = attrs
            .get(&over.id)
            .is_some_and(|(_, a)| propagation_is_locked(&a.propagation));
        if !(is_lock(&t, over, pin_root) && locked) {
            break;
        }
        ids.push(over.id);
    }
    ids
}

fn bpffs_mounts(root: &Path) -> Check {
    // lot 311 (bug hunt 1.4, F4): the table read as bytes — a user's FUSE
    // mount named with bytes that are not UTF-8 made it unreadable, and the
    // check said "not mounted"; a table that cannot be read is said so
    let bytes = crate::mountinfo::read_bytes(&root.join("proc/self/mountinfo"));
    let table = bytes.as_ref().map(|b| crate::mountinfo::parse(b));
    // Lot 365: the pin directory's lock (lot 359), recognised by what it is,
    // never by its path: the self-bind of the pin directory, private and
    // unbindable, the child of the whole bpffs at /sys/fs/bpf
    // (`pin_lock::state_in`, the agent's own test of it). It is no second
    // bpffs — it hides nothing, it holds the pins in place — and every
    // host with the agent showed "mounted 2×". Anything else at that path
    // (not a self-bind, shared, bindable, laid over the lock) still counts.
    let pin_root = crate::anti_tamper::pin_lock::pin_root();
    let lock = match &bytes {
        Ok(b) => own_pin_lock(b, &pin_root),
        Err(_) => Vec::new(),
    };
    let bpf: Vec<&crate::mountinfo::MountEntry> = match &table {
        Ok(t) => t
            .entries
            .iter()
            .filter(|m| m.fstype == "bpf" && !lock.contains(&m.id))
            .collect(),
        Err(_) => Vec::new(),
    };
    let lock_said = if !lock.is_empty() {
        format!(
            " (and the agent's pin lock at {}, not counted)",
            pin_root.display()
        )
    } else {
        String::new()
    };
    let at_std = bpf
        .iter()
        .any(|m| m.mount_point == Path::new("/sys/fs/bpf"));
    let (status, value) = match (&table, bpf.len()) {
        (Err(e), _) => (
            Status::Warn,
            format!("the mount table could not be read: {e}"),
        ),
        (_, 0) => (Status::Warn, "not mounted".to_string()),
        (_, 1) if at_std => (
            Status::Ok,
            format!("mounted once at /sys/fs/bpf{lock_said}"),
        ),
        (_, 1) => (Status::Warn, "mounted once, not at /sys/fs/bpf".to_string()),
        (_, n) => (
            Status::Warn,
            format!(
                "mounted {n}×{lock_said} — a second bpffs can hide pinned objects from the \
                 inventory"
            ),
        ),
    };
    // lot 311 (the review of #538, F2): lines not in the kernel's shape are
    // said, never dropped in silence (a bpffs among them is not counted)
    let (status, value) = match &table {
        Ok(t) if !t.malformed.is_empty() => (
            Status::Warn,
            format!(
                "{value}; {} line(s) of the mount table not in the kernel's shape, not counted",
                t.malformed.len()
            ),
        ),
        _ => (status, value),
    };
    Check {
        id: "bpffs",
        name: "bpffs mounted once at /sys/fs/bpf",
        status,
        value,
        fix: "mount bpffs once (`mount -t bpf bpf /sys/fs/bpf`, or the systemd sys-fs-bpf.mount unit) and investigate any extra bpffs mount",
    }
}

/// External audit DEP-001: a private admin key on the host is a credential
/// for whoever is root on it — COMBAT release, trusted-installer windows
/// (the anti-tamper suspended), overlay signatures.
fn admin_key(root: &Path) -> Check {
    let (found, unread) = admin_key_probe(root);
    let (status, value) = match unread.first() {
        _ if !found.is_empty() => (Status::Warn, found.join(", ")),
        // lot 385: a path not looked at is no key absent
        Some(u) => (Status::Unknown, u.said("")),
        None => (Status::Ok, "none at the bootstrap paths".to_string()),
    };
    Check {
        id: "admin_key",
        name: "admin private key off the host",
        status,
        value,
        fix: "move the admin private key offline (`mv <key> <offline media>`): on the host it lets root release COMBAT, open trusted-installer windows (the anti-tamper suspended) and sign overlays",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 385 (the external tester's F9b-2): `nn-admin host-check` run
    /// without root said `OK admin private key off the host — none at the
    /// bootstrap paths` with the key in `/root`, and `IMA not present` with
    /// IMA on. Every file the checks read is here, with a value that would
    /// pass, and none can be read by this user: no check says `OK`, and each
    /// one that could not look says so. (As root every file is read: the
    /// test needs another user.)
    #[test]
    fn a_check_that_cannot_read_never_says_ok() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root reads every file");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let files: &[(&str, &[u8])] = &[
            ("sys/kernel/security/lsm", b"lockdown,capability,bpf"),
            (
                "sys/kernel/security/lockdown",
                b"none [integrity] confidentiality",
            ),
            ("sys/kernel/security/ima/runtime_measurements_count", b"12"),
            ("proc/sys/kernel/unprivileged_bpf_disabled", b"2"),
            ("sys/module/module/parameters/sig_enforce", b"Y"),
            (
                "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                &[7, 0, 0, 0, 1],
            ),
            ("proc/sys/kernel/kexec_load_disabled", b"1"),
            ("proc/cmdline", b"cgroup_no_v1=all"),
            (
                "proc/cgroups",
                b"#subsys_name hierarchy num_cgroups enabled\nfreezer 0 1 1\n",
            ),
            ("proc/sys/kernel/osrelease", b"6.20.0"),
            ("root/northnarrow-admin.key", b"secret"),
            ("etc/ld.so.preload", b""),
        ];
        for (rel, body) in files {
            w(root, rel, body);
            std::fs::set_permissions(root.join(rel), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        // `/root` itself is root's
        std::fs::set_permissions(root.join("root"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let checks = run_in(root);
        let (found, unread) = admin_key_probe(root);
        std::fs::set_permissions(root.join("root"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert!(
            found.is_empty() && unread.len() == 1,
            "{found:?} {unread:?}"
        );
        let ok: Vec<String> = checks
            .iter()
            .filter(|c| c.status == Status::Ok)
            .map(|c| format!("{}: {}", c.id, c.value))
            .collect();
        assert!(ok.is_empty(), "OK without reading: {ok:?}");
        for id in [
            "bpf_lsm",
            "lockdown",
            "unprivileged_bpf",
            "module_sig_enforce",
            "secure_boot",
            "ima",
            "kexec_load_disabled",
            "admin_key",
            "cgroup_v1",
            "kernel_fixes",
        ] {
            let c = checks.iter().find(|c| c.id == id).unwrap();
            assert_eq!(c.status, Status::Unknown, "{id}: {}", c.value);
            assert!(c.value.starts_with(CANNOT_CHECK), "{id}: {}", c.value);
        }
        let table = render_table(&checks);
        assert!(
            table.contains("10 check(s) could not be read as this user — run it as root"),
            "{table}"
        );
        // the key readable: a WARN, and an absent file is said as absent
        let c = run_in(root)
            .into_iter()
            .find(|c| c.id == "admin_key")
            .unwrap();
        assert_eq!(
            (c.status, c.value.as_str()),
            (Status::Warn, "/root/northnarrow-admin.key")
        );
        assert_eq!(Unread::Absent.said("IMA not present"), "IMA not present");
    }

    /// Lot 385 (the review of #593, named): `nn-admin host-check` without
    /// root read a preload list naming a library in a directory this user
    /// cannot search as `OK present, loads nothing`, where root's run says
    /// `FAIL loads … into every program`. The row says it could not look,
    /// like every check that could not read, and names a path root would
    /// see before one nobody can (a link loop). (As root every directory is
    /// searched: the test needs another user.)
    #[test]
    fn host_check_without_root_never_says_ok_of_a_preload_library_it_could_not_see() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root searches every directory");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        w(
            root,
            "etc/ld.so.preload",
            b"/opt/loop.so /secret/libhook.so /secret/$LIB/libhook.so\n",
        );
        w(root, "secret/libhook.so", b"x");
        // a link to itself (ELOOP for every caller): not looked at either,
        // but a denied path is the one the row names (root would see it)
        std::fs::create_dir_all(root.join("opt")).unwrap();
        std::os::unix::fs::symlink("loop.so", root.join("opt/loop.so")).unwrap();
        let preload = || {
            run_in(root)
                .into_iter()
                .find(|c| c.id == "preload")
                .unwrap()
        };
        let mode = |m: u32| {
            std::fs::set_permissions(root.join("secret"), std::fs::Permissions::from_mode(m))
                .unwrap()
        };
        mode(0o000);
        let unseen = preload();
        let table = render_table(&run_in(root));
        mode(0o755);
        assert_ne!(
            unseen.status,
            Status::Ok,
            "OK without looking: {}",
            unseen.value
        );
        assert_eq!(unseen.status, Status::Unknown, "{}", unseen.value);
        assert_eq!(
            unseen.value,
            format!(
                "{CANNOT_CHECK} (/secret/libhook.so is not readable as this user); \
                 6 more path(s) the list names not looked at"
            )
        );
        assert!(
            table.contains("1 check(s) could not be read as this user"),
            "{table}"
        );
        // searchable: what root sees
        let seen = preload();
        assert_eq!(
            (seen.status, seen.value.as_str()),
            (
                Status::Fail,
                "loads /secret/libhook.so into every program: the agent and its watchdog refuse to start"
            )
        );
    }

    fn w(root: &Path, rel: &str, body: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// An executable `nft` at `rel`, its directories 0755 (the agent runs
    /// only a file nobody but its owner can change, in such directories).
    fn nft_at(root: &Path, rel: &str) {
        use std::os::unix::fs::PermissionsExt;
        w(root, rel, b"#!/bin/sh\n");
        let p = root.join(rel);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut dir = p.parent();
        while let Some(d) = dir {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
            if d == root {
                break;
            }
            dir = d.parent();
        }
    }

    #[test]
    fn hardened_host_is_all_ok() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        w(
            r,
            "sys/kernel/security/lsm",
            b"lockdown,capability,yama,selinux,bpf",
        );
        w(
            r,
            "sys/kernel/security/lockdown",
            b"none [integrity] confidentiality",
        );
        w(r, "proc/sys/kernel/unprivileged_bpf_disabled", b"2\n");
        w(r, "sys/module/module/parameters/sig_enforce", b"Y\n");
        w(
            r,
            "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            &[6, 0, 0, 0, 1],
        );
        w(
            r,
            "sys/kernel/security/ima/runtime_measurements_count",
            b"1234\n",
        );
        w(r, "proc/sys/kernel/kexec_load_disabled", b"1\n");
        w(r, "proc/self/mountinfo", b"36 25 0:30 / /sys/fs/bpf rw,nosuid shared:17 - bpf bpf rw,mode=700\n40 25 0:31 / /proc rw - proc proc rw\n");
        // admin.pub only: the private key went offline
        w(r, "etc/northnarrow/admin.pub", b"ab unlock\n");
        nft_at(r, "usr/sbin/nft");
        w(r, INSTALL_MANIFEST_REL, &manifest("attested", None));
        w(
            r,
            "proc/cmdline",
            b"BOOT_IMAGE=/vmlinuz root=/dev/sda1 cgroup_no_v1=all\n",
        );
        w(
            r,
            "proc/cgroups",
            b"#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpu\t0\t80\t1\nfreezer\t0\t80\t1\n",
        );
        w(r, "proc/sys/kernel/osrelease", b"6.19.1\n");
        let checks = run_in(r);
        assert_eq!(checks.len(), 14);
        assert_eq!(warn_count(&checks), 0, "{:?}", checks);
        assert_eq!(fail_count(&checks), 0, "{:?}", checks);
        assert!(
            checks.iter().all(|c| c.status == Status::Ok),
            "{:?}",
            checks
        );
        assert!(render_table(&checks).contains("14 check(s), 0 warning(s)"));
        assert!(!render_table(&checks).contains("failure(s)"));
    }

    fn kernel(files: &[(&str, &str)]) -> Check {
        let d = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            w(d.path(), rel, body.as_bytes());
        }
        kernel_fixes(d.path())
    }

    /// Lot 277: an upstream kernel's version decides — at or past each
    /// fix of its branch `ok`, below one `warn` with the CVE named; a
    /// branch the fix never reached (6.8, 5.14) is below it.
    #[test]
    fn an_upstream_kernel_is_judged_by_its_version() {
        let c = kernel(&[("proc/sys/kernel/osrelease", "6.6.143\n")]);
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        assert!(
            c.value
                .starts_with("6.6.143 from 6.6.143: CVE-2022-0847 fixed"),
            "{}",
            c.value
        );
        let c = kernel(&[("proc/sys/kernel/osrelease", "6.6.142\n")]);
        assert_eq!(c.status, Status::Warn);
        assert!(c.value.contains("CVE-2025-68736 MISSING"), "{}", c.value);
        assert!(c.value.contains("CVE-2024-42318 fixed"), "{}", c.value);
        let c = kernel(&[("proc/sys/kernel/osrelease", "6.8.12\n")]);
        assert_eq!(c.status, Status::Warn);
        assert!(c.value.contains("CVE-2024-42318 MISSING"), "{}", c.value);
        // 5.15: Dirty Pipe from 5.15.25, CVE-2022-30594 from 5.15.33
        let c = kernel(&[("proc/sys/kernel/osrelease", "5.15.30\n")]);
        assert!(c.value.contains("CVE-2022-0847 fixed"), "{}", c.value);
        assert!(c.value.contains("CVE-2022-30594 MISSING"), "{}", c.value);
        // older than the bugs: not affected (Landlock from 5.13, Dirty
        // Pipe from 5.8)
        let c = kernel(&[("proc/sys/kernel/osrelease", "5.4.300\n")]);
        assert!(
            c.value.contains("CVE-2022-0847 not affected"),
            "{}",
            c.value
        );
        assert!(
            c.value.contains("CVE-2024-42318 not affected"),
            "{}",
            c.value
        );
        // the review of #494, D3: 5.4 carries the ptrace fix from 5.4.189
        assert!(c.value.contains("CVE-2022-30594 fixed"), "{}", c.value);
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        let c = kernel(&[("proc/sys/kernel/osrelease", "5.4.188\n")]);
        assert!(c.value.contains("CVE-2022-30594 MISSING"), "{}", c.value);
        let c = kernel(&[("proc/sys/kernel/osrelease", "4.19.238\n")]);
        assert!(c.value.contains("CVE-2022-30594 fixed"), "{}", c.value);
        // the mainline release of each fix and every later one
        let c = kernel(&[("proc/sys/kernel/osrelease", "6.19.0-rc3\n")]);
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        assert_eq!(
            kernel(&[("proc/sys/kernel/osrelease", "7.0.0\n")]).status,
            Status::Ok
        );
        // nothing readable: unknown
        assert_eq!(kernel(&[]).status, Status::Unknown);
    }

    /// Lot 277: a distribution's kernel below a fix is `unknown`, never
    /// `ok`, and never `warn` either: the version cannot say. Ubuntu's
    /// signature and Debian's banner give the upstream version; a frozen
    /// enterprise number (`5.14.0-….el9`) gives none past its base.
    #[test]
    fn a_distribution_kernel_below_a_fix_is_unknown() {
        // Ubuntu 22.04: based on 5.15.131 — Dirty Pipe and CVE-2022-30594
        // fixed upstream, the Landlock fixes not in the number
        let c = kernel(&[
            ("proc/sys/kernel/osrelease", "5.15.0-91-generic\n"),
            (
                "proc/version_signature",
                "Ubuntu 5.15.0-91.101-generic 5.15.131\n",
            ),
        ]);
        assert_eq!(c.status, Status::Unknown, "{}", c.value);
        assert!(
            c.value
                .starts_with("5.15.131 from 5.15.0-91-generic (Ubuntu"),
            "{}",
            c.value
        );
        assert!(
            c.value
                .contains("CVE-2022-0847 fixed, CVE-2022-30594 fixed"),
            "{}",
            c.value
        );
        assert!(c.value.contains("CVE-2024-42318 unknown"), "{}", c.value);
        assert!(c.value.contains("Ubuntu backports fixes"), "{}", c.value);
        // without the signature the frozen 5.15.0 says nothing past 5.15.0
        let c = kernel(&[("proc/sys/kernel/osrelease", "5.15.0-91-generic\n")]);
        assert_eq!(c.status, Status::Unknown);
        assert!(c.value.contains("CVE-2022-0847 unknown"), "{}", c.value);
        // Debian 12: the kernel's own version, not the compiler's
        let c = kernel(&[
            ("proc/sys/kernel/osrelease", "6.1.0-26-amd64\n"),
            (
                "proc/version",
                "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-12                  (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP                  PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)\n",
            ),
        ]);
        assert_eq!(c.status, Status::Unknown, "{}", c.value);
        assert!(
            c.value
                .starts_with("6.1.112 from 6.1.0-26-amd64 (Debian 6.1.112-1)"),
            "{}",
            c.value
        );
        assert!(c.value.contains("CVE-2024-42318 fixed"), "{}", c.value);
        assert!(c.value.contains("CVE-2025-68736 unknown"), "{}", c.value);
        // Debian past every fix of its branch: ok
        let c = kernel(&[
            ("proc/sys/kernel/osrelease", "6.1.0-40-amd64\n"),
            (
                "proc/version",
                "Linux version 6.1.0-40-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.190-1\n",
            ),
        ]);
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        // the kernel's own version, wherever the compiler's stands
        let c = kernel(&[
            ("proc/sys/kernel/osrelease", "6.1.0-26-amd64\n"),
            (
                "proc/version",
                "Linux version 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 \
                 (2024-09-30) (gcc-12 (Debian 12.2.0-14) 12.2.0)\n",
            ),
        ]);
        assert!(c.value.starts_with("6.1.112 from"), "{}", c.value);
        // a frozen number with no banner (a Debian kernel read without
        // /proc/version): a distribution's, unknown below a fix; a plain
        // upstream number of the same branch: warn
        let c = kernel(&[("proc/sys/kernel/osrelease", "6.1.0-26-amd64\n")]);
        assert_eq!(c.status, Status::Unknown, "{}", c.value);
        assert!(c.value.contains("a distribution backports"), "{}", c.value);
        assert_eq!(
            kernel(&[("proc/sys/kernel/osrelease", "6.1.0\n")]).status,
            Status::Warn
        );
        // RHEL 9: frozen at 5.14.0, a branch no upstream fix reached
        let c = kernel(&[(
            "proc/sys/kernel/osrelease",
            "5.14.0-427.13.1.el9_4.x86_64\n",
        )]);
        assert_eq!(c.status, Status::Unknown, "{}", c.value);
        assert!(c.value.contains("Red Hat family backports"), "{}", c.value);
        // a signature of another branch is not this kernel's
        let c = kernel(&[
            ("proc/sys/kernel/osrelease", "6.8.12\n"),
            (
                "proc/version_signature",
                "Ubuntu 5.15.0-91.101-generic 5.15.131\n",
            ),
        ]);
        assert_eq!(c.status, Status::Warn, "{}", c.value);
    }

    /// Lot 277: the table as its sources publish it (read on 2026-11-03,
    /// `KERNEL_FIXES`'s documentation): a changed version is a change of
    /// the sources' reading, made here too — and each boundary judged.
    #[test]
    fn the_fix_table_is_the_sources() {
        type Row = (
            &'static str,
            (u32, u32, u32),
            Vec<(u32, u32, u32)>,
            (u32, u32),
        );
        let table: Vec<Row> = KERNEL_FIXES
            .iter()
            .map(|f| (f.cve, f.introduced, f.stable.to_vec(), f.mainline))
            .collect();
        assert_eq!(
            table,
            vec![
                (
                    "CVE-2022-0847",
                    (5, 8, 0),
                    vec![(5, 10, 102), (5, 15, 25), (5, 16, 11)],
                    (5, 17)
                ),
                (
                    "CVE-2022-30594",
                    (4, 3, 0),
                    vec![
                        (4, 19, 238),
                        (5, 4, 189),
                        (5, 10, 110),
                        (5, 15, 33),
                        (5, 16, 19),
                        (5, 17, 2)
                    ],
                    (5, 18)
                ),
                (
                    "CVE-2024-42318",
                    (5, 13, 0),
                    vec![(5, 15, 165), (6, 1, 103), (6, 6, 44), (6, 10, 3)],
                    (6, 11)
                ),
                (
                    "CVE-2025-68736",
                    (5, 13, 0),
                    vec![(6, 1, 189), (6, 6, 143), (6, 12, 80), (6, 18, 2)],
                    (6, 19)
                ),
            ]
        );
        let upstream = |v: (u32, u32, u32)| KernelVersion {
            version: v,
            release: String::new(),
            distro: None,
        };
        for f in KERNEL_FIXES {
            for (a, b, s) in f.stable {
                assert_eq!(
                    fix_state(f, &upstream((*a, *b, *s))),
                    FixState::Fixed,
                    "{}",
                    f.cve
                );
                assert_eq!(
                    fix_state(f, &upstream((*a, *b, s - 1))),
                    FixState::Missing,
                    "{} {a}.{b}.{}",
                    f.cve,
                    s - 1
                );
            }
            let (ma, mi) = f.mainline;
            assert_eq!(
                fix_state(f, &upstream((ma, mi, 0))),
                FixState::Fixed,
                "{}",
                f.cve
            );
            assert_eq!(
                fix_state(f, &upstream(f.introduced)),
                FixState::Missing,
                "{}",
                f.cve
            );
            let (ia, ib, _) = f.introduced;
            if ib > 0 {
                assert_eq!(
                    fix_state(f, &upstream((ia, ib - 1, 999))),
                    FixState::NotAffected,
                    "{}",
                    f.cve
                );
            }
            // a distribution's kernel below the fix: unknown, never ok
            let distro = KernelVersion {
                distro: Some("Ubuntu"),
                ..upstream(f.introduced)
            };
            assert_eq!(fix_state(f, &distro), FixState::Unknown, "{}", f.cve);
        }
    }

    /// Lot 277: every fix's branches lie between its first affected
    /// release and its mainline release, sorted, one per branch.
    #[test]
    fn the_fix_table_is_consistent() {
        for f in KERNEL_FIXES {
            let mut last = (0, 0);
            for (a, b, s) in f.stable {
                assert!((*a, *b, *s) > f.introduced, "{}", f.cve);
                assert!((*a, *b) < f.mainline, "{}", f.cve);
                assert!((*a, *b) > last, "{}: sorted, one per branch", f.cve);
                last = (*a, *b);
            }
            assert!(
                f.cve.starts_with("CVE-") && f.source.contains("kernel.org"),
                "{}",
                f.cve
            );
        }
        assert_eq!(parse_version("6.8.0-45-generic"), Some((6, 8, 0)));
        assert_eq!(parse_version("6.19-rc1"), Some((6, 19, 0)));
        assert_eq!(parse_version("x"), None);
    }

    /// Lot 277: kexec's load limits (6.6+) at 0 refuse every load; under
    /// lockdown alone a signed kernel still boots — still a warning.
    #[test]
    fn kexec_counts_its_load_limits() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        w(r, "proc/sys/kernel/kexec_load_disabled", b"0\n");
        assert_eq!(kexec_load_disabled(r).status, Status::Warn);
        w(
            r,
            "sys/kernel/security/lockdown",
            b"none [integrity] confidentiality\n",
        );
        let c = kexec_load_disabled(r);
        assert_eq!(c.status, Status::Warn);
        // the review of #494, D7: one sentence, no run of spaces
        assert!(
            c.value
                .contains("a signed kernel still boots with another command line"),
            "{}",
            c.value
        );
        w(r, "proc/sys/kernel/kexec_load_limit_reboot", b"0\n");
        assert_eq!(
            kexec_load_disabled(r).status,
            Status::Warn,
            "one limit only"
        );
        w(r, "proc/sys/kernel/kexec_load_limit_panic", b"0\n");
        let c = kexec_load_disabled(r);
        assert_eq!(c.status, Status::Ok);
        assert!(c.value.contains("no load left"), "{}", c.value);
    }

    /// Lot 277: `modules_disabled=1` refuses every module load.
    #[test]
    fn modules_disabled_counts_as_module_signature_enforcement() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        w(r, "sys/module/module/parameters/sig_enforce", b"N\n");
        assert_eq!(module_sig_enforce(r).status, Status::Warn);
        w(r, "proc/sys/kernel/modules_disabled", b"1\n");
        let c = module_sig_enforce(r);
        assert_eq!(c.status, Status::Ok);
        assert!(c.value.contains("modules_disabled=1"), "{}", c.value);
    }

    /// Lot 273b: the v1 controllers a root can mount, unless the kernel's
    /// command line refuses them — all, or by name.
    /// Lot 377 (named): a preload list that makes every program load a
    /// library is a host the agent cannot run on — `fail`, the file named,
    /// the fix shown, a failures line under the table; an absent, empty or
    /// inert list is `ok` and said; a list that cannot be read as one fails.
    #[test]
    fn host_check_fails_a_loadable_preload_list() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        let check = |r: &Path| run_in(r).into_iter().find(|c| c.id == "preload").unwrap();
        let c = check(r);
        assert_eq!((c.status, c.value.as_str()), (Status::Ok, "absent"));
        w(r, "etc/ld.so.preload", b"# nothing\n");
        let c = check(r);
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        assert!(c.value.contains("loads nothing (empty)"), "{}", c.value);
        w(r, "etc/ld.so.preload", b"/opt/gone/libx.so\n");
        let c = check(r);
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        assert!(c.value.contains("1 name(s)"), "{}", c.value);
        w(r, "usr/lib/x86_64-linux-gnu/libnnlog.so", b"");
        w(r, "etc/ld.so.preload", b"/opt/gone/libx.so libnnlog.so\n");
        let checks = run_in(r);
        let c = checks.iter().find(|c| c.id == "preload").unwrap();
        assert_eq!(c.status, Status::Fail, "{}", c.value);
        assert!(
            c.value.contains("/usr/lib/x86_64-linux-gnu/libnnlog.so"),
            "{}",
            c.value
        );
        assert_eq!(fail_count(&checks), 1);
        let table = render_table(&checks);
        assert!(table.contains("FAIL  Library preload list"), "{table}");
        assert!(table.contains(PRELOAD_FIX), "{table}");
        assert!(table.contains("1 failure(s)"), "{table}");
        let json = serde_json::to_string(&checks).unwrap();
        assert!(json.contains("\"status\":\"fail\""), "{json}");
        // a list that is no file the loader reads as one
        std::fs::remove_file(r.join("etc/ld.so.preload")).unwrap();
        std::fs::create_dir(r.join("etc/ld.so.preload")).unwrap();
        let c = check(r);
        assert_eq!(c.status, Status::Fail, "{}", c.value);
        assert!(c.value.contains("cannot be judged"), "{}", c.value);
    }

    #[test]
    fn cgroup_v1_names_what_root_can_mount() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        assert_eq!(cgroup_v1(r).status, Status::Unknown);
        w(
            r,
            "proc/cgroups",
            b"#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpu\t0\t80\t1\nfreezer\t0\t80\t1\ndevices\t0\t80\t1\nnet_cls\t0\t1\t0\n",
        );
        w(r, "proc/cmdline", b"root=/dev/sda1 quiet\n");
        let c = cgroup_v1(r);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.value, "mountable as cgroup v1: freezer, devices");
        w(r, "proc/cmdline", b"root=/dev/sda1 cgroup_no_v1=devices\n");
        assert_eq!(cgroup_v1(r).value, "mountable as cgroup v1: freezer");
        w(
            r,
            "proc/cmdline",
            b"root=/dev/sda1 cgroup_no_v1=freezer,devices\n",
        );
        assert_eq!(cgroup_v1(r).status, Status::Ok);
        w(r, "proc/cmdline", b"cgroup_no_v1=all\n");
        let c = cgroup_v1(r);
        assert_eq!(
            (c.status, c.value.as_str()),
            (Status::Ok, "cgroup_no_v1=all")
        );
    }

    fn manifest(provenance: &str, verify_override: Option<&str>) -> Vec<u8> {
        let ov = verify_override
            .map(|f| format!(r#""verify_override":"{f}","#))
            .unwrap_or_default();
        format!(
            r#"{{"version":"0.0.1","provenance":"{provenance}",{ov}"bin_dir":"/usr/local/bin",
                "files":{{"northnarrow-agent":"00"}},"tarball_sha256":null}}"#
        )
        .into_bytes()
    }

    /// External audit DEP-007, lab PR 220: anything below `attested` is a
    /// warning, and the flag that accepted it is named. Lot 354:
    /// `signed-checksums` reached with no flag is OK.
    #[test]
    fn install_provenance_warns_below_attested() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        assert_eq!(install_provenance(r).status, Status::Unknown);
        for (prov, flag, status) in [
            ("attested", None, Status::Ok),
            ("signed-checksums", None, Status::Ok),
            ("signed-checksums", Some("--allow-unverified"), Status::Warn),
            ("checksums", Some("--allow-unverified"), Status::Warn),
            ("checksums", None, Status::Warn),
            ("manifest", Some("--allow-manifest-only"), Status::Warn),
            ("manifest", Some("--allow-unverified"), Status::Warn),
            ("source-tree", Some("--allow-unverified"), Status::Warn),
            ("source-tree", Some("--source-tree"), Status::Warn),
            ("unverified", Some("--no-verify"), Status::Warn),
            ("package", None, Status::Warn),
            ("source-tree", None, Status::Warn),
        ] {
            w(r, INSTALL_MANIFEST_REL, &manifest(prov, flag));
            let c = install_provenance(r);
            assert_eq!(c.status, status, "{prov}");
            assert!(c.value.starts_with(prov), "{}", c.value);
            if let Some(f) = flag {
                assert!(c.value.contains(f), "{}", c.value);
            }
        }
        w(r, INSTALL_MANIFEST_REL, b"{not json");
        assert_eq!(install_provenance(r).status, Status::Warn);
    }

    /// Lab follow-up (lab PR 165): a host without `nft` stays a WARN, and
    /// names `--without-nftables` when the install manifest recorded it.
    /// External audit ATP-014 (NN-AUD-262): an `nft` under `/usr/local`
    /// (systemd's default service PATH) is not the agent's, and is not
    /// reported as found; a system directory's is.
    #[test]
    fn nft_check_names_the_install_override() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        let c = nft_tool(r);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.value, "not installed");
        assert!(c.fix.contains("subsystem_degraded"), "{}", c.fix);
        let with = String::from_utf8(manifest("source-tree", Some("--source-tree")))
            .unwrap()
            .replacen(
                r#""bin_dir""#,
                r#""prerequisite_overrides":["--without-nftables"],"bin_dir""#,
                1,
            );
        w(r, INSTALL_MANIFEST_REL, with.as_bytes());
        let c = nft_tool(r);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.value, "not installed (accepted with --without-nftables)");
        nft_at(r, "usr/local/sbin/nft");
        let c = nft_tool(r);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.value, "not installed (accepted with --without-nftables)");
        nft_at(r, "usr/sbin/nft");
        let c = nft_tool(r);
        assert_eq!(c.status, Status::Ok);
        assert_eq!(c.value, "/usr/sbin/nft");
        // a copy others can change is reported, not used
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                r.join("usr/sbin/nft"),
                std::fs::Permissions::from_mode(0o777),
            )
            .unwrap();
        }
        let c = nft_tool(r);
        assert_eq!(c.status, Status::Warn);
        assert!(c.value.starts_with("not trusted: "), "{}", c.value);
    }

    #[test]
    fn lab_guest_defaults_warn_on_the_right_items() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        w(
            r,
            "sys/kernel/security/lsm",
            b"lockdown,capability,landlock,yama,apparmor,bpf",
        );
        w(
            r,
            "sys/kernel/security/lockdown",
            b"[none] integrity confidentiality",
        );
        w(r, "proc/sys/kernel/unprivileged_bpf_disabled", b"2\n");
        w(r, "sys/module/module/parameters/sig_enforce", b"N\n");
        // no EFI variable: a QEMU guest without UEFI
        w(
            r,
            "sys/kernel/security/ima/runtime_measurements_count",
            b"0\n",
        );
        w(r, "proc/sys/kernel/kexec_load_disabled", b"0\n");
        w(r, "proc/self/mountinfo", b"36 25 0:30 / /sys/fs/bpf rw shared:17 - bpf bpf rw\n37 25 0:32 / /mnt/bpf2 rw - bpf bpf rw\n");
        // the lab keeps the bootstrap key where install.sh used to write it
        w(r, "etc/northnarrow/admin.key", b"0123456789abcdef\n");
        // and installs from its source tree
        w(
            r,
            INSTALL_MANIFEST_REL,
            &manifest("source-tree", Some("--source-tree")),
        );
        let checks = run_in(r);
        let by_id = |id: &str| checks.iter().find(|c| c.id == id).unwrap().status;
        assert_eq!(by_id("bpf_lsm"), Status::Ok);
        assert_eq!(by_id("lockdown"), Status::Warn);
        assert_eq!(by_id("unprivileged_bpf"), Status::Ok);
        assert_eq!(by_id("module_sig_enforce"), Status::Warn);
        assert_eq!(by_id("secure_boot"), Status::Unknown);
        assert_eq!(by_id("ima"), Status::Warn);
        assert_eq!(by_id("kexec_load_disabled"), Status::Warn);
        assert_eq!(by_id("bpffs"), Status::Warn);
        assert_eq!(by_id("admin_key"), Status::Warn);
        // the Debian 12 lab image has no nftables (CMB-006 lab note)
        assert_eq!(by_id("nft"), Status::Warn);
        assert_eq!(by_id("install_provenance"), Status::Warn);
        assert_eq!(by_id("kernel_fixes"), Status::Unknown);
        assert_eq!(warn_count(&checks), 8);
        let table = render_table(&checks);
        assert!(table.contains("fix: boot with `lockdown=integrity`"));
        assert!(table.contains("recommended on every host"));
        assert!(table.contains("mounted 2×"));
        assert!(table.contains("/etc/northnarrow/admin.key"));
    }

    /// Lot 311 (bug hunt 1.4, F4): a user's FUSE mount named with bytes that
    /// are not UTF-8 does not blind the bpffs check — on main the table was
    /// unreadable as text and the check said "not mounted" (or missed a
    /// second bpffs).
    #[test]
    fn a_non_utf8_mount_does_not_hide_the_bpffs() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        let fuse: &[u8] = b"57 25 0:44 / /home/u/\xff rw,nosuid,nodev - fuse.x x rw,user_id=1000\n";
        let mut once = b"36 25 0:30 / /sys/fs/bpf rw shared:17 - bpf bpf rw\n".to_vec();
        once.extend_from_slice(fuse);
        w(r, "proc/self/mountinfo", &once);
        assert_eq!(bpffs_mounts(r).status, Status::Ok);
        let mut twice = once.clone();
        twice.extend_from_slice(b"37 25 0:32 / /mnt/bpf2 rw - bpf bpf rw\n");
        w(r, "proc/self/mountinfo", &twice);
        let c = bpffs_mounts(r);
        assert_eq!(c.status, Status::Warn);
        assert!(c.value.contains("mounted 2"), "{}", c.value);
        let e = tempfile::tempdir().unwrap();
        assert!(bpffs_mounts(e.path()).value.contains("could not be read"));
        // the review of #538 (F2): a source `-` is a mount; a line not in
        // the kernel's shape is said
        let mut dash = b"36 25 0:30 / /sys/fs/bpf rw shared:17 - bpf bpf rw\n".to_vec();
        dash.extend_from_slice(b"57 25 0:44 / /home/u/m rw - fuse.x - rw\n");
        w(r, "proc/self/mountinfo", &dash);
        assert_eq!(bpffs_mounts(r).status, Status::Ok);
        dash.extend_from_slice(b"58 25 0:45 / /tmp/x rw tmpfs x rw\n");
        w(r, "proc/self/mountinfo", &dash);
        let c = bpffs_mounts(r);
        assert_eq!(c.status, Status::Warn);
        assert!(c.value.contains("not in the kernel's shape"), "{}", c.value);
    }

    /// Lot 365: since lot 359 every host with the agent showed "bpffs
    /// mounted 2×": the pin directory's lock is a second bpffs mount. It is
    /// recognised by what it is (the self-bind of the pin directory, private
    /// and unbindable, the child of the whole bpffs at /sys/fs/bpf, or a lock
    /// stacked on it) — never by its path: a bpffs at that path that is not
    /// the lock, the lock shared or bindable, a mount over it, and any other
    /// bpffs still warn.
    #[test]
    fn the_agent_s_pin_lock_is_not_a_second_bpffs() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        let base = "1 0 252:1 / / rw shared:1 - ext4 /dev/vda1 rw\n\
                    20 1 0:20 / /sys rw shared:7 - sysfs sysfs rw\n\
                    30 20 0:30 / /sys/fs/bpf rw shared:9 - bpf bpf rw,mode=700\n";
        let lock = |prop: &str| {
            let prop = if prop.is_empty() {
                String::new()
            } else {
                format!(" {prop}")
            };
            format!(
                "90 30 0:30 /northnarrow /sys/fs/bpf/northnarrow rw,relatime{prop} - bpf bpf \
                 rw,mode=700\n"
            )
        };
        let check = |lines: &str| {
            w(
                r,
                "proc/self/mountinfo",
                format!("{base}{lines}").as_bytes(),
            );
            bpffs_mounts(r)
        };
        let c = check(&lock("unbindable"));
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        assert!(c.value.contains("the agent's pin lock"), "{}", c.value);
        // a lock stacked on the lock is the lock
        let c = check(&format!(
            "{}91 90 0:30 /northnarrow /sys/fs/bpf/northnarrow rw unbindable - bpf bpf rw\n",
            lock("unbindable")
        ));
        assert_eq!(c.status, Status::Ok, "{}", c.value);
        for (what, n, lines) in [
            ("the lock shared", 2, lock("shared:120 unbindable")),
            (
                "a lock stacked on the lock, shared",
                2,
                format!(
                    "{}91 90 0:30 /northnarrow /sys/fs/bpf/northnarrow rw shared:121 unbindable - \
                     bpf bpf rw\n",
                    lock("unbindable")
                ),
            ),
            ("the lock bindable", 2, lock("")),
            (
                "another bpffs at the pin path",
                2,
                "90 30 0:92 / /sys/fs/bpf/northnarrow rw unbindable - bpf bpf rw\n".to_string(),
            ),
            (
                "another directory of the bpffs at the pin path",
                2,
                "90 30 0:30 /other /sys/fs/bpf/northnarrow rw unbindable - bpf bpf rw\n"
                    .to_string(),
            ),
            (
                "the lock and a bpffs elsewhere",
                2,
                format!(
                    "{}95 1 0:96 / /mnt/bpf2 rw - bpf bpf rw\n",
                    lock("unbindable")
                ),
            ),
            (
                "a bpffs over the lock (the lock no longer in place)",
                3,
                format!(
                    "{}91 90 0:97 / /sys/fs/bpf/northnarrow rw unbindable - bpf bpf rw\n",
                    lock("unbindable")
                ),
            ),
        ] {
            let c = check(&lines);
            assert_eq!(c.status, Status::Warn, "{what}: {}", c.value);
            assert!(
                c.value.contains(&format!("mounted {n}×")),
                "{what}: {}",
                c.value
            );
        }
        // without the lock, once is once
        assert_eq!(check("").status, Status::Ok);
    }

    #[test]
    fn empty_tree_is_unknown_not_warn_except_bpffs() {
        let d = tempfile::tempdir().unwrap();
        let checks = run_in(d.path());
        // nothing readable: every check is Unknown except bpffs (no mount =
        // Warn), nft (no binary = Warn), admin_key (no key file = Ok) and
        // preload (lot 377: no list = Ok, nothing preloaded)
        for c in &checks {
            if c.id == "bpffs" || c.id == "nft" {
                assert_eq!(c.status, Status::Warn);
            } else if c.id == "admin_key" || c.id == "preload" {
                assert_eq!(c.status, Status::Ok);
            } else {
                assert_eq!(c.status, Status::Unknown, "{}", c.id);
            }
        }
    }

    /// Lot 280b (named): lockdown in confidentiality mode is a warning with
    /// its own fix — integrity is the recommendation; none keeps its own.
    #[test]
    fn lockdown_confidentiality_is_a_warning_with_its_own_fix() {
        let at = |v: &[u8]| {
            let d = tempfile::tempdir().unwrap();
            w(d.path(), "sys/kernel/security/lockdown", v);
            lockdown(d.path())
        };
        let c = at(b"none integrity [confidentiality]\n");
        assert_eq!(c.status, Status::Warn);
        assert!(c.fix.contains("instead of `confidentiality`"), "{}", c.fix);
        assert!(c.fix.contains("bpf_probe_read_kernel"), "{}", c.fix);
        let i = at(b"none [integrity] confidentiality\n");
        assert_eq!(i.status, Status::Ok);
        let n = at(b"[none] integrity confidentiality\n");
        assert_eq!(n.status, Status::Warn);
        assert!(
            n.fix
                .starts_with("boot with `lockdown=integrity` (Secure Boot"),
            "{}",
            n.fix
        );
        assert_ne!(n.fix, c.fix);
    }

    /// Lockdown in integrity mode refuses unsigned modules whatever
    /// `sig_enforce` says: the check reports it as enforced (lab: Ubuntu
    /// 22.04 with `lockdown=integrity`, sig_enforce=N).
    #[test]
    fn lockdown_integrity_counts_as_module_signature_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        w(
            r,
            "sys/kernel/security/lockdown",
            b"none [integrity] confidentiality\n",
        );
        w(r, "sys/module/module/parameters/sig_enforce", b"N\n");
        let c = module_sig_enforce(r);
        assert_eq!(c.status, Status::Ok);
        assert!(c.value.contains("lockdown=integrity"), "{}", c.value);
        w(
            r,
            "sys/kernel/security/lockdown",
            b"[none] integrity confidentiality\n",
        );
        assert_eq!(module_sig_enforce(r).status, Status::Warn);
    }

    /// External audit DEP-001: both bootstrap locations are found, an empty
    /// or non-regular entry is not a key.
    #[test]
    fn admin_private_keys_on_the_host_are_reported() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        assert!(admin_keys_on_host(r).is_empty());
        w(r, "root/northnarrow-admin.key", b"");
        std::fs::create_dir_all(r.join("etc/northnarrow/admin.key")).unwrap();
        assert!(
            admin_keys_on_host(r).is_empty(),
            "empty file or a directory"
        );
        w(r, "root/northnarrow-admin.key", b"k\n");
        assert_eq!(admin_keys_on_host(r), vec!["/root/northnarrow-admin.key"]);
        std::fs::remove_dir(r.join("etc/northnarrow/admin.key")).unwrap();
        w(r, "etc/northnarrow/admin.key", b"k\n");
        let c = admin_key(r);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(
            c.value,
            "/etc/northnarrow/admin.key, /root/northnarrow-admin.key"
        );
    }
}
