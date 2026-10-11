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
//! file under `/sys` or `/proc`; [`run_in`] takes a root prefix so tests
//! build a synthetic tree.

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
    ]
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
    let (status, value) = match read(root, "/sys/module/module/parameters/sig_enforce") {
        Some(v) if v == "Y" => (Status::Ok, v),
        Some(v) => (Status::Warn, v),
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
        let checks = run_in(r);
        assert_eq!(checks.len(), 8);
        assert_eq!(warn_count(&checks), 0, "{:?}", checks);
        assert!(
            checks.iter().all(|c| c.status == Status::Ok),
            "{:?}",
            checks
        );
        assert!(render_table(&checks).contains("8 check(s), 0 warning(s)"));
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
        assert_eq!(warn_count(&checks), 5);
        let table = render_table(&checks);
        assert!(table.contains("fix: boot with `lockdown=integrity`"));
        assert!(table.contains("mounted 2×"));
    }

    #[test]
    fn empty_tree_is_unknown_not_warn_except_bpffs() {
        let d = tempfile::tempdir().unwrap();
        let checks = run_in(d.path());
        // nothing readable: every check is Unknown except bpffs (no mount = Warn)
        for c in &checks {
            if c.id == "bpffs" {
                assert_eq!(c.status, Status::Warn);
            } else {
                assert_eq!(c.status, Status::Unknown, "{}", c.id);
            }
        }
    }
}
