//! Lot 273c (the review of #490): the host's type- and slice-wide drop-ins
//! that reach our units, quarantined.
//!
//! systemd applies `service.d/*.conf` to every service (ours included),
//! `slice.d/*.conf` to every slice and `system.slice.d/*.conf` to the slice
//! both units run in. The units' own drop-in directories refuse a new
//! entry outside a window (NOCREATE), these do not: they are the host's. A
//! `MemoryMax=4K` dropped there is refused at the cgroup file after a
//! reload, but systemd applies it to the units' fresh cgroups at the next
//! start or boot — an OOM loop; an `Environment=NN_ANTI_TAMPER_ALLOW_DEGRADED=1`
//! or an `ExecStart=` reaches the agent the same way.
//!
//! The agent's integrity round reads `/etc/systemd/system` and
//! `/run/systemd/system`'s three directories (the agent's unit makes them,
//! empty, and lets the agent write there): a drop-in that sets a directive
//! of [`DANGEROUS`] (or an environment variable of [`DANGEROUS_ENV`]) is
//! moved to `/var/lib/northnarrow/quarantine/dropins/` (with where it was),
//! systemd is asked for a reload (its copy loses the drop-in), and the
//! move is a signed `unit_dropin_quarantined` drift. A drop-in with only
//! other directives (a `TimeoutStopSec=`, a proxy variable) is left: a
//! finding, as before. The vendor directories (`/usr/lib/systemd/system`)
//! are the packages': findings only.

use std::path::{Path, PathBuf};

/// The host directories whose drop-ins reach the units, under the two
/// writable unit directories.
pub const HOST_DIRS: &[&str] = &[
    "/etc/systemd/system/service.d",
    "/etc/systemd/system/slice.d",
    "/etc/systemd/system/system.slice.d",
    "/run/systemd/system/service.d",
    "/run/systemd/system/slice.d",
    "/run/systemd/system/system.slice.d",
];

/// Where a quarantined drop-in goes.
pub const QUARANTINE_DIR: &str = "/var/lib/northnarrow/quarantine/dropins";

/// The directives that stop, starve, limit or replace a service: resource
/// control, scheduling, limits, killing, what it runs and sees.
pub const DANGEROUS: &[&str] = &[
    "MemoryMax",
    "MemoryHigh",
    "MemoryLimit",
    "MemorySwapMax",
    "MemoryZSwapMax",
    "TasksMax",
    "CPUQuota",
    "CPUQuotaPeriodSec",
    "CPUWeight",
    "StartupCPUWeight",
    "CPUShares",
    "StartupCPUShares",
    "AllowedCPUs",
    "StartupAllowedCPUs",
    "AllowedMemoryNodes",
    "StartupAllowedMemoryNodes",
    "IOWeight",
    "StartupIOWeight",
    "IODeviceWeight",
    "IOReadBandwidthMax",
    "IOWriteBandwidthMax",
    "IOReadIOPSMax",
    "IOWriteIOPSMax",
    "IODeviceLatencyTargetSec",
    "BlockIOWeight",
    "BlockIOReadBandwidth",
    "BlockIOWriteBandwidth",
    "OOMPolicy",
    "OOMScoreAdjust",
    "ManagedOOMMemoryPressure",
    "ManagedOOMSwap",
    "Slice",
    "Delegate",
    "DeviceAllow",
    "DevicePolicy",
    "IPAddressDeny",
    "IPIngressFilterPath",
    "IPEgressFilterPath",
    "SocketBindDeny",
    "RestrictNetworkInterfaces",
    "Nice",
    "CPUSchedulingPolicy",
    "CPUSchedulingPriority",
    "CPUAffinity",
    "NUMAPolicy",
    "NUMAMask",
    "IOSchedulingClass",
    "IOSchedulingPriority",
    "LimitCPU",
    "LimitAS",
    "LimitDATA",
    "LimitRSS",
    "LimitNOFILE",
    "LimitMEMLOCK",
    "LimitNPROC",
    "LimitSTACK",
    "LimitFSIZE",
    "KillMode",
    "KillSignal",
    "SendSIGKILL",
    "FinalKillSignal",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecStop",
    "ExecStopPost",
    "ExecReload",
    "BindPaths",
    "BindReadOnlyPaths",
    "TemporaryFileSystem",
    "InaccessiblePaths",
    "ReadOnlyPaths",
    "RootDirectory",
    "RootImage",
    "MountImages",
    "ExtensionImages",
    "SystemCallFilter",
    "RestrictAddressFamilies",
    "EnvironmentFile",
    "User",
    "DynamicUser",
];

/// The environment variables that change the agent: its own switches, the
/// dynamic loader's.
pub const DANGEROUS_ENV: &[&str] = &["NN_", "LD_", "RUST_", "MALLOC_", "GLIBC_"];

/// The first directive of `text` that is dangerous (`Condition*=` and
/// `Assert*=` are: they skip or fail the start), or an `Environment=` that
/// sets a dangerous variable.
pub fn dangerous_directive(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if DANGEROUS.contains(&key) || key.starts_with("Condition") || key.starts_with("Assert") {
            return Some(key.to_string());
        }
        if key == "Environment" {
            for assignment in value.split_whitespace() {
                let var = assignment.trim_matches('"').split('=').next().unwrap_or("");
                if DANGEROUS_ENV.iter().any(|p| var.starts_with(p)) {
                    return Some(format!("Environment={var}"));
                }
            }
        }
    }
    None
}

/// One drop-in moved, or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantined {
    pub from: PathBuf,
    pub to: Option<PathBuf>,
    pub directive: String,
    pub error: Option<String>,
}

impl Quarantined {
    pub fn detail(&self) -> String {
        match (&self.to, &self.error) {
            (Some(to), None) => format!(
                "{} sets {} for every unit it reaches (ours too): moved to {}",
                self.from.display(),
                self.directive,
                to.display()
            ),
            (_, e) => format!(
                "{} sets {} for every unit it reaches (ours too): NOT moved ({})",
                self.from.display(),
                self.directive,
                e.as_deref().unwrap_or("?")
            ),
        }
    }
}

/// Quarantine the dangerous drop-ins of `dirs` into `quarantine` (`now`:
/// the file name's stamp). A drop-in that cannot be read, or is not a
/// regular file, is left (the integrity round reports it).
pub fn quarantine(dirs: &[&Path], quarantine: &Path, now: u64) -> Vec<Quarantined> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            let from = e.path();
            if from.extension().and_then(|x| x.to_str()) != Some("conf") {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&from) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&from) else {
                continue;
            };
            let Some(directive) = dangerous_directive(&text) else {
                continue;
            };
            let name: String = from
                .to_string_lossy()
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let to = quarantine.join(format!("{now}-{name}"));
            let moved = std::fs::create_dir_all(quarantine)
                .and_then(|()| std::fs::write(&to, &text))
                .and_then(|()| std::fs::remove_file(&from));
            out.push(match moved {
                Ok(()) => Quarantined {
                    from,
                    to: Some(to),
                    directive,
                    error: None,
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&to);
                    Quarantined {
                        from,
                        to: None,
                        directive,
                        error: Some(e.to_string()),
                    }
                }
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_an_exec_a_condition_or_a_switch_is_dangerous_and_a_timeout_is_not() {
        assert_eq!(
            dangerous_directive("[Service]\nMemoryMax=4K\n").as_deref(),
            Some("MemoryMax")
        );
        assert_eq!(
            dangerous_directive("[Service]\nExecStart=\nExecStart=/bin/true").as_deref(),
            Some("ExecStart")
        );
        assert_eq!(
            dangerous_directive("[Unit]\nConditionPathExists=/nope").as_deref(),
            Some("ConditionPathExists")
        );
        assert_eq!(
            dangerous_directive(
                "[Service]\nEnvironment=\"http_proxy=x\" NN_ANTI_TAMPER_ALLOW_DEGRADED=1"
            )
            .as_deref(),
            Some("Environment=NN_ANTI_TAMPER_ALLOW_DEGRADED")
        );
        assert_eq!(
            dangerous_directive("[Service]\nEnvironment=LD_PRELOAD=/x.so").as_deref(),
            Some("Environment=LD_PRELOAD")
        );
        assert_eq!(
            dangerous_directive(
                "[Service]\nTimeoutStopSec=30\nEnvironment=http_proxy=http://p:3128"
            ),
            None
        );
        assert_eq!(dangerous_directive("# MemoryMax=4K\n; TasksMax=1\n"), None);
    }

    #[test]
    fn a_dangerous_drop_in_is_moved_and_a_harmless_one_left() {
        let host = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let dir = host.path().join("service.d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("zz-oom.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        std::fs::write(
            dir.join("10-timeout.conf"),
            "[Service]\nTimeoutStopSec=30\n",
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "MemoryMax=4K").unwrap();
        let r = quarantine(&[dir.as_path()], q.path(), 1700000000);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].directive, "MemoryMax");
        assert!(!dir.join("zz-oom.conf").exists());
        assert!(dir.join("10-timeout.conf").exists());
        assert!(dir.join("notes.txt").exists());
        let to = r[0].to.as_ref().unwrap();
        assert_eq!(
            std::fs::read_to_string(to).unwrap(),
            "[Service]\nMemoryMax=4K\n"
        );
        assert!(to
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("1700000000-"));
        assert!(r[0]
            .detail()
            .contains("sets MemoryMax for every unit it reaches (ours too): moved to"));
    }
}
