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
//! synthetic tree.

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
    ]
}

/// External audit DEP-007: the install manifest `install.sh` writes,
/// relative to the root.
pub const INSTALL_MANIFEST_REL: &str = "etc/northnarrow/install-manifest.json";

/// External audit DEP-007: how far `install.sh` could verify the release
/// the installed binaries came from. Only `checksums` (the tarball against
/// the release's `SHA256SUMS`) and `attested` (the SLSA attestation) rest
/// on something outside the tree; `manifest` is the tree vouching for
/// itself, and `source-tree`, `unverified` and `package` verified nothing
/// on this host. The agent boots at every level (a lab or a developer host
/// must keep working), so the level is reported here.
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
                    "attested" | "checksums" => Status::Ok,
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
        fix: "install from the release tarball with its SHA256SUMS (next to the tree, or `--tarball` + `--sums`), and `gh` or `cosign` for the attestation: `manifest`, `source-tree`, `unverified` and `package` mean nothing outside the installed tree vouched for these binaries",
    }
}

/// External audit CMB-014: where `nft` may be installed — the directories
/// of systemd's default `PATH` for a service, which the agent searches
/// (lab PR 165 added `/usr/local`). The per-process outbound block (a
/// BlockOutbound verdict, the COMBAT soft egress block of INVESTIGATE) is an
/// nftables rule: without `nft` the offender is not contained while the
/// agent analyses it.
const NFT_PATHS: &[&str] = &[
    "usr/local/sbin/nft",
    "usr/local/bin/nft",
    "usr/sbin/nft",
    "usr/bin/nft",
    "sbin/nft",
    "bin/nft",
];

/// The `install.sh` flag that accepts a host without `nft` (lab PR 165).
const WITHOUT_NFT_FLAG: &str = "--without-nftables";

/// A missing `nft` is a WARN like every other check: host-check has no
/// level above it, and its exit status (2) already marks the host. The
/// refusal belongs to the install paths: the packages depend on nftables
/// and `install.sh` refuses without it unless `--without-nftables`, which
/// is named here when the install manifest records it (lab PR 165).
fn nft_tool(root: &Path) -> Check {
    let found = NFT_PATHS.iter().find(|rel| root.join(rel).is_file());
    let (status, value) = match found {
        Some(rel) => (Status::Ok, format!("/{rel}")),
        None => {
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
        fix: "install nftables (`apt-get install nftables` / `dnf install nftables`) — without `nft` neither a BlockOutbound verdict nor the COMBAT soft egress block drops the offender's traffic (the agent records a signed subsystem_degraded at boot, and each episode records the failure and shortens INVESTIGATE)",
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
        fix: "add `lsm=…,bpf` to the kernel command line (keep the distro list, append bpf) and reboot",
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
        fix: "boot with `lockdown=integrity` (Secure Boot enables it on most distros): blocks unsigned modules, kexec of unsigned kernels, /dev/mem and other runtime kernel modification by root",
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
    let (status, value) = match read(root, "/sys/module/module/parameters/sig_enforce") {
        Some(v) if v == "Y" => (Status::Ok, v),
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
    let (status, value) = match read(root, "/proc/sys/kernel/kexec_load_disabled") {
        Some(v) if v == "1" => (Status::Ok, v),
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
        w(r, "usr/sbin/nft", b"");
        w(r, INSTALL_MANIFEST_REL, &manifest("checksums", None));
        let checks = run_in(r);
        assert_eq!(checks.len(), 11);
        assert_eq!(warn_count(&checks), 0, "{:?}", checks);
        assert!(
            checks.iter().all(|c| c.status == Status::Ok),
            "{:?}",
            checks
        );
        assert!(render_table(&checks).contains("11 check(s), 0 warning(s)"));
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

    /// External audit DEP-007: anything below `checksums` is a warning, and
    /// the flag that accepted it is named.
    #[test]
    fn install_provenance_warns_below_checksums() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        assert_eq!(install_provenance(r).status, Status::Unknown);
        for (prov, flag, status) in [
            ("attested", None, Status::Ok),
            ("checksums", None, Status::Ok),
            ("manifest", Some("--allow-manifest-only"), Status::Warn),
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
    /// names `--without-nftables` when the install manifest recorded it; an
    /// `nft` under `/usr/local` (systemd's default service PATH) is found.
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
        w(r, "usr/local/sbin/nft", b"");
        let c = nft_tool(r);
        assert_eq!(c.status, Status::Ok);
        assert_eq!(c.value, "/usr/local/sbin/nft");
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
        assert_eq!(warn_count(&checks), 8);
        let table = render_table(&checks);
        assert!(table.contains("fix: boot with `lockdown=integrity`"));
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
