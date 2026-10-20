//! External audit PROC-005: who installed a kernel module file.
//!
//! R018 told a rootkit from a module by the path alone: a `.ko` under
//! `/lib/modules` was "standard". Whoever loads a module holds
//! `CAP_SYS_MODULE` and can write there, so copying the image under
//! `/lib/modules` first turned the kill into a Medium alert. A module file
//! there is installed by a package (dpkg, rpm) or built by DKMS; one that
//! neither installed was put there by hand.
//!
//! [`ModuleOwners::of`] answers from the package database: on Debian and
//! its family the `.list` files of `/var/lib/dpkg/info` (the module paths
//! read once, again when `/var/lib/dpkg/status` changes); on the RPM family
//! `rpm -qf`; DKMS by its registry (`/var/lib/dkms/<module>`) for a file
//! under an `updates/dkms` or `extra` directory. A host with neither
//! database is [`Provenance::Unknown`], judged as before. Paths are compared
//! with `/usr` dropped: a merged-`/usr` host reports `/usr/lib/modules`
//! while packages list `/lib/modules`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use parking_lot::Mutex;

/// Who put a module file where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// A package lists it.
    Package,
    /// DKMS built it (a registered module, in its install directory).
    Dkms,
    /// Neither: copied or built there by hand.
    Unowned,
    /// No package database to ask (not a dpkg or rpm host).
    Unknown,
}

pub struct ModuleOwners {
    /// `/` in production; a fixture tree in tests.
    root: PathBuf,
    /// dpkg's module paths (`/usr` dropped) and the status file's mtime
    /// they were read at.
    dpkg: Mutex<Option<(Option<SystemTime>, HashSet<String>)>>,
}

impl Default for ModuleOwners {
    fn default() -> Self {
        Self::new("/")
    }
}

impl ModuleOwners {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            dpkg: Mutex::new(None),
        }
    }

    /// Who installed the module file at `path` (absolute, on the host).
    /// The rule engine runs on the runtime: the first lookup reads every
    /// dpkg list, and `rpm -qf` is a process to wait for, so both run off
    /// its worker.
    pub fn of(&self, path: &str) -> Provenance {
        crate::fim::drain::off_the_runtime(|| self.lookup(path))
    }

    fn lookup(&self, path: &str) -> Provenance {
        let key = without_usr(path);
        if self.dkms_built(&key) {
            return Provenance::Dkms;
        }
        let info = self.root.join("var/lib/dpkg/info");
        if info.is_dir() {
            return if self.dpkg_lists(&key) {
                Provenance::Package
            } else {
                Provenance::Unowned
            };
        }
        if self.root.join("var/lib/rpm").is_dir() || self.root.join("usr/lib/sysimage/rpm").is_dir()
        {
            return match rpm_owns(path) {
                Some(true) => Provenance::Package,
                Some(false) => Provenance::Unowned,
                None => Provenance::Unknown,
            };
        }
        Provenance::Unknown
    }

    /// `key` is listed by an installed package (dpkg).
    fn dpkg_lists(&self, key: &str) -> bool {
        let status = std::fs::metadata(self.root.join("var/lib/dpkg/status"))
            .and_then(|m| m.modified())
            .ok();
        let mut cache = self.dpkg.lock();
        let stale = cache.as_ref().is_none_or(|(at, _)| *at != status);
        if stale {
            *cache = Some((status, self.read_dpkg_module_paths()));
        }
        cache.as_ref().is_some_and(|(_, set)| set.contains(key))
    }

    /// Every path under `lib/modules/` some `.list` file names, `/usr`
    /// dropped.
    fn read_dpkg_module_paths(&self) -> HashSet<String> {
        let mut set = HashSet::new();
        let Ok(dir) = std::fs::read_dir(self.root.join("var/lib/dpkg/info")) else {
            return set;
        };
        for entry in dir.flatten() {
            if entry.path().extension().is_none_or(|e| e != "list") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in text.lines() {
                if line.contains("/lib/modules/") {
                    set.insert(without_usr(line));
                }
            }
        }
        set
    }

    /// A file in a DKMS install directory whose module DKMS has registered.
    fn dkms_built(&self, key: &str) -> bool {
        if !(key.contains("/updates/dkms/") || key.contains("/extra/")) {
            return false;
        }
        let Some(name) = module_name(key) else {
            return false;
        };
        let registry = self.root.join("var/lib/dkms");
        // DKMS registers `<name>` or, for a package of several modules,
        // the package's name: the file must sit in one of its trees.
        registry.join(&name).is_dir() || dkms_tree_has(&registry, &name)
    }
}

/// `rpm -qf --quiet PATH`: owned (`Some(true)`), not owned, or `None` when
/// rpm cannot be asked. External audit ATP-014 (NN-AUD-262): the system
/// directories' `rpm` ([`crate::trusted_bin`]), not the first on `PATH` —
/// one planted in `/usr/local/bin` that exits 0 made every module file
/// "packaged". None trusted: `None`, judged as a host without a database.
fn rpm_owns(path: &str) -> Option<bool> {
    let rpm = match crate::trusted_bin::resolve("rpm") {
        Ok(rpm) => rpm,
        Err(e) => {
            tracing::warn!(error = %e, "R018 provenance: rpm not run");
            return None;
        }
    };
    let status = rpm
        .command()
        .args(["-qf", "--quiet", path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    Some(status.success())
}

/// A registered DKMS package holds a built module of this name.
fn dkms_tree_has(registry: &Path, name: &str) -> bool {
    let Ok(pkgs) = std::fs::read_dir(registry) else {
        return false;
    };
    pkgs.flatten()
        .any(|pkg| walk_finds(&pkg.path(), &format!("{name}.ko"), 6))
}

fn walk_finds(dir: &Path, prefix: &str, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk_finds(&p, prefix, depth - 1)
        } else {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        }
    })
}

/// `/usr/lib/modules/…` → `/lib/modules/…`.
fn without_usr(path: &str) -> String {
    path.strip_prefix("/usr").unwrap_or(path).to_string()
}

/// `…/name.ko[.xz|.zst|.gz]` → `name`.
fn module_name(path: &str) -> Option<String> {
    let file = path.rsplit('/').next()?;
    let stem = file.split(".ko").next()?;
    (!stem.is_empty()).then(|| stem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn dpkg_host() -> TempDir {
        let t = TempDir::new().unwrap();
        let info = t.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(t.path().join("var/lib/dpkg/status"), "Package: x\n").unwrap();
        std::fs::write(
            info.join("linux-modules-6.8.0-1-generic.list"),
            "/lib/modules/6.8.0-1-generic/kernel/drivers/net/e1000e.ko.zst\n/boot\n",
        )
        .unwrap();
        t
    }

    #[test]
    fn a_packaged_module_is_the_packages_whatever_the_usr_alias() {
        let t = dpkg_host();
        let o = ModuleOwners::new(t.path());
        for p in [
            "/lib/modules/6.8.0-1-generic/kernel/drivers/net/e1000e.ko.zst",
            "/usr/lib/modules/6.8.0-1-generic/kernel/drivers/net/e1000e.ko.zst",
        ] {
            assert_eq!(o.of(p), Provenance::Package, "{p}");
        }
    }

    /// The PROC-005 shape: an image copied under /lib/modules.
    #[test]
    fn a_module_copied_under_lib_modules_is_unowned() {
        let t = dpkg_host();
        let o = ModuleOwners::new(t.path());
        assert_eq!(
            o.of("/usr/lib/modules/6.8.0-1-generic/kernel/drivers/net/rk.ko"),
            Provenance::Unowned
        );
    }

    #[test]
    fn a_dkms_module_is_dkms_built_only_when_registered() {
        let t = dpkg_host();
        let o = ModuleOwners::new(t.path());
        let p = "/lib/modules/6.8.0-1-generic/updates/dkms/zfs.ko.zst";
        assert_eq!(o.of(p), Provenance::Unowned, "not registered");
        std::fs::create_dir_all(t.path().join("var/lib/dkms/zfs/2.2.2")).unwrap();
        assert_eq!(o.of(p), Provenance::Dkms);
        // a package of several modules: found in its tree
        let built = t
            .path()
            .join("var/lib/dkms/nvidia/550/6.8.0-1-generic/x86_64/module");
        std::fs::create_dir_all(&built).unwrap();
        std::fs::write(built.join("nvidia-uvm.ko.zst"), b"").unwrap();
        assert_eq!(
            o.of("/lib/modules/6.8.0-1-generic/updates/dkms/nvidia-uvm.ko.zst"),
            Provenance::Dkms
        );
    }

    #[test]
    fn a_new_package_is_seen_once_dpkg_status_changes() {
        let t = dpkg_host();
        let o = ModuleOwners::new(t.path());
        let p = "/lib/modules/6.8.0-2-generic/kernel/x.ko";
        assert_eq!(o.of(p), Provenance::Unowned);
        std::fs::write(
            t.path()
                .join("var/lib/dpkg/info/linux-modules-6.8.0-2-generic.list"),
            format!("{p}\n"),
        )
        .unwrap();
        // dpkg rewrites its status file on every transaction
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(t.path().join("var/lib/dpkg/status"), "Package: y\n").unwrap();
        let _ = std::fs::File::open(t.path().join("var/lib/dpkg/status"))
            .and_then(|f| f.set_modified(SystemTime::now() + std::time::Duration::from_secs(5)));
        assert_eq!(o.of(p), Provenance::Package);
    }

    #[test]
    fn no_package_database_is_unknown() {
        let t = TempDir::new().unwrap();
        assert_eq!(
            ModuleOwners::new(t.path()).of("/lib/modules/6.8/kernel/x.ko"),
            Provenance::Unknown
        );
    }
}
