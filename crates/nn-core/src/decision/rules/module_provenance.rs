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
//!
//! R12b (lab PR 269, plan §3.4: "module_provenance usa una cache di
//! `PackageOwnership`"): the package database is asked by the module-load
//! pump, on its own thread, when it reads the load's record
//! ([`ModuleOwners::refresh`]: a `stat` of dpkg's status, its lists, or an
//! `rpm -qf` process), and the answer is kept per file ([`OWNERSHIP`]); R018
//! judges the load on that answer ([`ModuleOwners::of`]) — no file read, no
//! process on the decision's thread. A file no pump asked about (the
//! replay, the tests) is asked about there, as before.

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::SystemTime;

use parking_lot::Mutex;

use crate::decision::host::DecisionHost;

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

/// R12b (lab PR 269): the package database's answers the module-load pump
/// asked for, per (host root, module file without `/usr`) — the latest for
/// each file, which R018 judges the load the pump read on. A host fact,
/// one per process; bounded ([`OWNERSHIP_KEYS`]: full, it starts again).
static OWNERSHIP: LazyLock<parking_lot::Mutex<HashMap<(PathBuf, String), Provenance>>> =
    LazyLock::new(Default::default);
/// The files [`OWNERSHIP`] keeps answers for at most.
pub const OWNERSHIP_KEYS: usize = 4096;

/// R08b (lab PR 251): `H` is the host whose `rpm` it asks and whose work
/// it keeps off the async runtime ([`DecisionHost`]; the agent's is
/// `LinuxHost`).
pub struct ModuleOwners<H: DecisionHost> {
    /// `/` in production; a fixture tree in tests.
    root: PathBuf,
    /// dpkg's module paths (`/usr` dropped) and the status file's mtime
    /// they were read at.
    dpkg: Mutex<Option<(Option<SystemTime>, HashSet<String>)>>,
    host: PhantomData<fn() -> H>,
}

impl<H: DecisionHost> Default for ModuleOwners<H> {
    fn default() -> Self {
        Self::new(H::HOST_ROOT)
    }
}

impl<H: DecisionHost> ModuleOwners<H> {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            dpkg: Mutex::new(None),
            host: PhantomData,
        }
    }

    /// Who installed the module file at `path` (absolute, on the host):
    /// R12b, the answer the module-load pump asked for when it read the
    /// load ([`Self::refresh`]); a file no pump asked about is asked about
    /// here — the first lookup reads every dpkg list, and `rpm -qf` is a
    /// process to wait for, so both run off the runtime's worker.
    pub fn of(&self, path: &str) -> Provenance {
        let key = (self.root.clone(), without_usr(path));
        if let Some(p) = OWNERSHIP.lock().get(&key) {
            return *p;
        }
        H::off_the_runtime(|| self.lookup(path))
    }

    /// R12b (lab PR 269): ask the package database who installed `path`
    /// now, and keep the answer for the decision ([`Self::of`]) — the
    /// module-load pump's call, on its own thread, for every load it reads.
    pub fn refresh(&self, path: &str) -> Provenance {
        let p = self.lookup(path);
        let mut kept = OWNERSHIP.lock();
        if kept.len() >= OWNERSHIP_KEYS {
            kept.clear();
        }
        kept.insert((self.root.clone(), without_usr(path)), p);
        p
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
            return match rpm_owns::<H>(path) {
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
/// directories' `rpm` (the host's: the agent's `trusted_bin`), not the
/// first on `PATH` — one planted in `/usr/local/bin` that exits 0 made
/// every module file "packaged". None trusted: `None`, judged as a host
/// without a database.
fn rpm_owns<H: DecisionHost>(path: &str) -> Option<bool> {
    match H::rpm_owns(path) {
        Ok(owned) => owned,
        Err(e) => {
            tracing::warn!(error = %e, "R018 provenance: rpm not run");
            None
        }
    }
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
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type ModuleOwners = super::ModuleOwners<H>;
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

    /// R12b: the answer the pump asked for is the one the rule reads —
    /// without the database (here: the answer kept while the database says
    /// otherwise until the next refresh, as the pump's next read of a load
    /// of the file would refresh it).
    #[test]
    fn the_rule_reads_the_answer_the_pump_asked_for() {
        let t = dpkg_host();
        let owners = ModuleOwners::new(t.path());
        let hand = "/lib/modules/6.8.0-1-generic/extra/rk.ko";
        assert_eq!(owners.refresh(hand), Provenance::Unowned);
        // the database changes (a package now lists it): the decision still
        // reads the answer of the load's time, without asking
        let info = t.path().join("var/lib/dpkg/info");
        std::fs::write(info.join("rk.list"), format!("{hand}\n")).unwrap();
        std::fs::write(
            t.path().join("var/lib/dpkg/status"),
            "Package: rk\nchanged\n",
        )
        .unwrap();
        assert_eq!(owners.of(hand), Provenance::Unowned, "the pump's answer");
        // the pump's next read asks again
        assert_eq!(owners.refresh(hand), Provenance::Package);
        assert_eq!(owners.of(hand), Provenance::Package);
        // another root's answers are its own
        let other = dpkg_host();
        assert_eq!(
            ModuleOwners::new(other.path()).of(hand),
            Provenance::Unowned
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
