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
    ]
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
///   4.3 (commit 13c4a90119d2); fixed in 5.10.110, 5.15.33, 5.16.19,
///   5.17.2 and mainline 5.18 (commit ee1fee900537): the CVE record
///   ("before 5.17.2"), `ChangeLog-5.10.110`, `-5.15.33`, `-5.16.19`,
///   `-5.17.2`, `-5.18`.
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
        stable: &[(5, 10, 110), (5, 15, 33), (5, 16, 19), (5, 17, 2)],
        mainline: (5, 18),
        source: "https://www.cve.org/CVERecord?id=CVE-2022-30594 ; cdn.kernel.org ChangeLog-5.10.110, -5.15.33, -5.16.19, -5.17.2, -5.18",
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
            value: "osrelease unreadable".to_string(),
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
    let (status, value) = match read(root, "/proc/cgroups") {
        None => (Status::Unknown, "/proc/cgroups unreadable".to_string()),
        Some(table) => {
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
/// verified nothing on this host. The agent boots at every level (a lab or
/// a developer host must keep working), so the level is reported here.
fn install_provenance(root: &Path) -> Check {
    let path = root.join(INSTALL_MANIFEST_REL);
    let (status, value) = match std::fs::read_to_string(&path) {
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
        fix: "install from the release tarball (next to the tree, or `--tarball`) with `gh` or `cosign` for its tag-bound attestation (install.sh refuses less without `--allow-unverified`): `checksums`, `manifest`, `source-tree`, `unverified` and `package` mean nothing proved where these binaries were built",
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
            let accepted = std::fs::read_to_string(root.join(INSTALL_MANIFEST_REL))
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
    ADMIN_KEY_PATHS
        .iter()
        .filter(|rel| {
            std::fs::metadata(root.join(rel))
                .map(|m| m.is_file() && m.len() > 0)
                .unwrap_or(false)
        })
        .map(|rel| format!("/{rel}"))
        .collect()
}

/// Number of `Warn` checks in `checks`.
pub fn warn_count(checks: &[Check]) -> usize {
    checks.iter().filter(|c| c.status == Status::Warn).count()
}

/// Human table, one line per check.
pub fn render_table(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        let tag = match c.status {
            Status::Ok => "OK  ",
            Status::Warn => "WARN",
            Status::Unknown => "n/a ",
        };
        out.push_str(&format!("{tag}  {:<32} {}\n", c.name, c.value));
        if c.status == Status::Warn && !c.fix.is_empty() {
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
    out
}

fn read(root: &Path, rel: &str) -> Option<String> {
    let p: PathBuf = root.join(rel.trim_start_matches('/'));
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn bpf_lsm(root: &Path) -> Check {
    let (status, value) = match read(root, "/sys/kernel/security/lsm") {
        Some(list) if list.split(',').any(|l| l == "bpf") => (Status::Ok, list),
        Some(list) => (Status::Warn, list),
        None => (Status::Unknown, "securityfs not readable".to_string()),
    };
    Check {
        id: "bpf_lsm",
        name: "BPF LSM in the active LSM list",
        status,
        value,
        fix: "append `bpf` to the LSM list the kernel runs (never a fixed `lsm=` list: it can switch SELinux or AppArmor off; docs/operator/KERNEL_COMPATIBILITY.md, \"Enabling the bpf LSM\") and reboot",
    }
}

fn lockdown(root: &Path) -> Check {
    let (status, value) = match read(root, "/sys/kernel/security/lockdown") {
        Some(s) if s.contains("[integrity]") || s.contains("[confidentiality]") => (Status::Ok, s),
        Some(s) => (Status::Warn, s),
        None => (Status::Unknown, "lockdown LSM not present".to_string()),
    };
    Check {
        id: "lockdown",
        name: "Kernel lockdown mode",
        status,
        value,
        fix: "boot with `lockdown=integrity` (Secure Boot enables it on most distros) — recommended on every host the agent defends: without it root can rewrite the running kernel (an unsigned module, /dev/mem, kexec of an unsigned kernel, a kprobe's write) and remove the agent's hooks with it, which no hook of the agent can refuse",
    }
}

fn unprivileged_bpf(root: &Path) -> Check {
    let (status, value) = match read(root, "/proc/sys/kernel/unprivileged_bpf_disabled") {
        Some(v) if v == "1" || v == "2" => (Status::Ok, v),
        Some(v) => (Status::Warn, v),
        None => (Status::Unknown, "sysctl absent".to_string()),
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
    let (status, value) = match read(root, "/sys/module/module/parameters/sig_enforce") {
        Some(v) if v == "Y" => (Status::Ok, v),
        Some(v) if modules_off => (
            Status::Ok,
            format!("{v} (every module load refused: modules_disabled=1)"),
        ),
        Some(v) => match lockdown_mode {
            Some(mode) => (
                Status::Ok,
                format!("{v} (unsigned modules refused by lockdown={mode})"),
            ),
            None => (Status::Warn, v),
        },
        None => (
            Status::Unknown,
            "parameter absent (CONFIG_MODULE_SIG off?)".to_string(),
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
    let (status, value) = match std::fs::read(&p) {
        Ok(bytes) if bytes.len() >= 5 && bytes[4] == 1 => (Status::Ok, "enabled".to_string()),
        Ok(bytes) if bytes.len() >= 5 => (Status::Warn, "disabled".to_string()),
        Ok(_) => (Status::Unknown, "efivar unreadable".to_string()),
        Err(_) => (
            Status::Unknown,
            "no EFI variable (legacy BIOS or VM without UEFI)".to_string(),
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
    let count = read(root, "/sys/kernel/security/ima/runtime_measurements_count").or_else(|| {
        read(
            root,
            "/sys/kernel/security/integrity/ima/runtime_measurements_count",
        )
    });
    let (status, value) = match count {
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 => (Status::Ok, format!("{n} measurements")),
            _ => (Status::Warn, format!("{v} measurements (no policy loaded)")),
        },
        None => (
            Status::Unknown,
            "IMA not present in this kernel".to_string(),
        ),
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
    let (status, value) = match read(root, "/proc/sys/kernel/kexec_load_disabled") {
        Some(v) if v == "1" => (Status::Ok, v),
        Some(v) if limits_zero => (
            Status::Ok,
            format!("{v} (kexec_load_limit_reboot and _panic 0: no load left)"),
        ),
        Some(v) if lockdown_on => (
            Status::Warn,
            format!(
                "{v} (lockdown refuses an unsigned image; a signed kernel still boots with                  another command line)"
            ),
        ),
        Some(v) => (Status::Warn, v),
        None => (
            Status::Unknown,
            "sysctl absent (CONFIG_KEXEC off)".to_string(),
        ),
    };
    Check {
        id: "kexec_load_disabled",
        name: "kexec disabled",
        status,
        value,
        fix: "`sysctl -w kernel.kexec_load_disabled=1` (one-way until reboot; persist in /etc/sysctl.d/) — kexec boots a different kernel without a reboot the sensor would notice",
    }
}

fn bpffs_mounts(root: &Path) -> Check {
    let mounts = read(root, "/proc/self/mountinfo").unwrap_or_default();
    let bpf: Vec<&str> = mounts
        .lines()
        .filter(|l| {
            // mountinfo: … - <fstype> <source> <options>
            l.split(" - ")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                == Some("bpf")
        })
        .collect();
    let at_std = bpf
        .iter()
        .any(|l| l.split_whitespace().nth(4) == Some("/sys/fs/bpf"));
    let (status, value) = match bpf.len() {
        0 => (Status::Warn, "not mounted".to_string()),
        1 if at_std => (Status::Ok, "mounted once at /sys/fs/bpf".to_string()),
        1 => (Status::Warn, "mounted once, not at /sys/fs/bpf".to_string()),
        n => (
            Status::Warn,
            format!("mounted {n}× — a second bpffs can hide pinned objects from the inventory"),
        ),
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
    let found = admin_keys_on_host(root);
    let (status, value) = if found.is_empty() {
        (Status::Ok, "none at the bootstrap paths".to_string())
    } else {
        (Status::Warn, found.join(", "))
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
        assert_eq!(checks.len(), 13);
        assert_eq!(warn_count(&checks), 0, "{:?}", checks);
        assert!(
            checks.iter().all(|c| c.status == Status::Ok),
            "{:?}",
            checks
        );
        assert!(render_table(&checks).contains("13 check(s), 0 warning(s)"));
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
        assert!(c.value.contains("CVE-2022-30594 MISSING"), "{}", c.value);
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
                    vec![(5, 10, 110), (5, 15, 33), (5, 16, 19), (5, 17, 2)],
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
        assert!(
            c.value.contains("a signed kernel still boots"),
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
    /// warning, and the flag that accepted it is named.
    #[test]
    fn install_provenance_warns_below_attested() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        assert_eq!(install_provenance(r).status, Status::Unknown);
        for (prov, flag, status) in [
            ("attested", None, Status::Ok),
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

    #[test]
    fn empty_tree_is_unknown_not_warn_except_bpffs() {
        let d = tempfile::tempdir().unwrap();
        let checks = run_in(d.path());
        // nothing readable: every check is Unknown except bpffs (no mount =
        // Warn), nft (no binary = Warn) and admin_key (no key file = Ok)
        for c in &checks {
            if c.id == "bpffs" || c.id == "nft" {
                assert_eq!(c.status, Status::Warn);
            } else if c.id == "admin_key" {
                assert_eq!(c.status, Status::Ok);
            } else {
                assert_eq!(c.status, Status::Unknown, "{}", c.id);
            }
        }
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
