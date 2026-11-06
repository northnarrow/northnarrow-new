//! Lot 285: the kernel's module-load judge, armed and fed by the agent.
//!
//! The judge itself is in the kernel (`agent-ebpf/src/module_load.rs`, its
//! verdicts `common::module_judge`): a `finit_module` of a file the trust
//! map does not vouch for, and an `init_module` of a buffer, are refused
//! outside a signed trusted-installer window in the deny mode. This
//! controller fills the map ([`scan`]: the running kernel's tree walked,
//! each module file classified), gives the kernel the package managers'
//! images (the write history's lineage) and the tree's root, and sets the
//! mode — after the first fill, so a judge with an empty map never refuses
//! a module the tree vouches for. It looks at the tree again every
//! [`FULL_EVERY`], at once when the kernel records a write in it, and when
//! the policy changes.
//!
//! The mode is the rule policy's for `R018_KernelModuleLoad`: `enforce`
//! the deny mode, `alert`, `audit` or `off` the record mode, no line the
//! default ([`DEFAULT_MODE`]). The signed `module-allow <module>` lines are
//! the per-module opt-outs, honoured only from a policy whose signature
//! the agent verified. A DKMS or akmods build its registry vouches for,
//! written since boot outside a recognised package transaction, is let
//! through and recorded under every policy but `enforce R018`
//! ([`Desired::unattested`], the coordinator's matrix).

pub mod kernel;
pub mod scan;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use common::module_judge::{
    mode, trust_flag, ModuleTrust, MODULE_PKG_IMAGES_MAX, MODULE_TRUST_MAX,
};
use common::wire::InodeKey;
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::decision::rule_policy::{Mode, RulePolicy};

/// The rule whose policy mode is the kernel judge's.
pub const RULE: &str = "R018_KernelModuleLoad";

/// The judge's mode without a policy line for [`RULE`]. Lot 285 measured
/// the benign corpus before choosing it (docs/operator/RULE_POLICY.md §2.4).
pub const DEFAULT_MODE: u64 = mode::DENY;

/// A full look at the tree at least this often.
pub const FULL_EVERY: Duration = Duration::from_secs(30);
/// How often the controller polls the write history's generation and the
/// policy.
const POLL: Duration = Duration::from_millis(250);
/// Untrusted files named in the journal per look.
const NAMED_MAX: usize = 20;
/// Package managers the judge's lineage knows besides the posture's list:
/// dnf5 (Fedora 41 on; `/usr/bin/dnf` links to it there).
const EXTRA_PKG_IMAGES: &[&str] = &["/usr/bin/dnf5"];

/// What the policy asks of the judge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    pub mode: u64,
    /// The signed per-module opt-outs (module names, `_` for `-`).
    pub opt_outs: BTreeSet<String>,
    /// A DKMS or akmods build its registry vouches for, written since boot
    /// outside a recognised package transaction, goes in the map (let
    /// through, recorded High): every policy but `enforce R018`.
    pub unattested: bool,
}

impl Default for Desired {
    fn default() -> Self {
        Self {
            mode: DEFAULT_MODE,
            opt_outs: BTreeSet::new(),
            unattested: true,
        }
    }
}

/// The policy in force for the judge (the agent's start and `nn-admin
/// policy set` write it; the controller reads it every poll). A host fact,
/// one per process.
static DESIRED: LazyLock<Mutex<Desired>> = LazyLock::new(Default::default);

/// The controller's last report (`state`), for the status and the tests.
static STATE: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new("not started".to_string()));

/// The judge's mode for `policy`: `enforce` → deny, any other mode →
/// record, no line → [`DEFAULT_MODE`].
pub fn mode_of(policy: &RulePolicy) -> u64 {
    match policy.mode(RULE) {
        None => DEFAULT_MODE,
        Some(Mode::Enforce) => mode::DENY,
        Some(_) => mode::RECORD,
    }
}

/// An unattested DKMS or akmods build is let through (recorded) under
/// `policy`: every policy but `enforce R018`.
pub fn unattested_of(policy: &RulePolicy) -> bool {
    policy.mode(RULE) != Some(Mode::Enforce)
}

/// The judge's part of `policy`: its mode, and its `module-allow` lines
/// when `signed` (the text applied is the signed one; an unsigned policy
/// loaded through `NN_OVERLAY_ALLOW_UNSIGNED` honours none). The detail of
/// a signed degradation when lines are withheld.
pub fn apply_policy(policy: &RulePolicy, signed: bool) -> Option<String> {
    let names: BTreeSet<String> = policy.module_opt_outs().map(str::to_string).collect();
    let count = names.len();
    *DESIRED.lock() = Desired {
        mode: mode_of(policy),
        opt_outs: if signed { names } else { BTreeSet::new() },
        unattested: unattested_of(policy),
    };
    (!signed && count > 0).then(|| {
        format!(
            "{}: {count} module-allow line(s) NOT honoured — the policy was loaded without a \
             valid signature (NN_OVERLAY_ALLOW_UNSIGNED=1): those modules' files stay untrusted",
            policy.source
        )
    })
}

/// The policy in force for the judge.
pub fn desired() -> Desired {
    DESIRED.lock().clone()
}

/// The controller's last report.
pub fn state() -> String {
    STATE.lock().clone()
}

fn set_state(s: String) {
    *STATE.lock() = s;
}

/// The mode's name.
pub fn mode_name(m: u64) -> &'static str {
    match m {
        mode::DENY => "deny",
        mode::RECORD => "record",
        _ => "not armed",
    }
}

/// Whether this kernel's offsets let the judge read a file's owner and
/// change time: without them it trusts no file, and the deny mode is never
/// armed (the record mode instead, signed degraded).
pub fn offsets_resolved() -> bool {
    use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
    let Some(r) = crate::anti_tamper::btf_revalidate::resolved() else {
        return true; // unarmed: the compiled 6.8 offsets apply
    };
    [
        slot::INODE_I_CTIME_SEC_OFFSET,
        slot::INODE_I_CTIME_NSEC_OFFSET,
        slot::INODE_I_UID_OFFSET,
    ]
    .iter()
    .all(|s| {
        r.values
            .iter()
            .any(|(k, v)| k == s && *v != BTF_OFFSETS_ABSENT)
    })
}

/// What a look classifies the tree's files with: the policy's part
/// (`want`) and the host's.
fn inputs_of<'a>(
    want: &'a Desired,
    release: &'a str,
    tree: &'a Path,
    boot_sec: i64,
    dkms_registry: &'a Path,
    history: Option<nn_linux::module_writes::History>,
) -> scan::Inputs<'a> {
    scan::Inputs {
        release,
        tree,
        boot_sec,
        dkms_registry,
        opt_outs: &want.opt_outs,
        unattested: want.unattested,
        history_since: history_since(history),
    }
}

/// From when the kernel's write history covers every write: the pinned
/// history's (`nn_linux::module_writes`); none, or not reliable: never
/// (every file changed since boot is one the history does not cover).
pub fn history_since(history: Option<nn_linux::module_writes::History>) -> (i64, u32) {
    history.and_then(|h| h.since).unwrap_or((i64::MAX, 0))
}

/// rpm's file digests of the tree (path → algorithm, hex).
type RpmIndex = HashMap<String, (u32, String)>;

/// When the controller last looked, at which write generation, for which
/// policy and package database.
type LastLook = (Instant, u64, Desired, Option<SystemTime>);

/// The controller's view of the tree and what it wrote.
struct Controller {
    kernel: kernel::Kernel,
    release: String,
    tree: PathBuf,
    deny_ok: bool,
    /// What the trust map holds (the kernel's copy).
    mirror: HashMap<InodeKey, ModuleTrust>,
    pkg_images: Vec<InodeKey>,
    cache: scan::PackagedCache,
    dpkg: crate::execq::pkgtrust::PackageTrust,
    rpm: Option<(Option<SystemTime>, RpmIndex)>,
    last: Option<LastLook>,
    armed: Option<u64>,
}

/// The running kernel's release.
fn release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.contains('/'))
}

fn mtime(p: &str) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// The package database's change stamp (dpkg's status, rpm's database).
fn db_stamp() -> Option<SystemTime> {
    mtime("/var/lib/dpkg/status")
        .or_else(|| mtime("/var/lib/rpm"))
        .or_else(|| mtime("/usr/lib/sysimage/rpm"))
}

fn rpm_host() -> bool {
    !Path::new("/var/lib/dpkg/info").is_dir()
        && (Path::new("/var/lib/rpm").is_dir() || Path::new("/usr/lib/sysimage/rpm").is_dir())
}

impl Controller {
    /// The package managers' images in the kernel: added as found (a
    /// running package manager keeps its old image across its own
    /// upgrade), replaced whole only when the map is full. A `#!` script
    /// among them (dnf, yum: Python) is matched by the file its exec named
    /// (`MODULE_PKG_SCRIPTS`), an executable by its image.
    fn refresh_pkg_images(&mut self) {
        let mut changed = false;
        for p in crate::posture::lineage::PACKAGE_MANAGER_EXES
            .iter()
            .chain(EXTRA_PKG_IMAGES)
        {
            if let Some(k) = crate::execpol::kernel::trusted_image_key(Path::new(p)) {
                let k = InodeKey {
                    dev: k.dev,
                    ino: k.ino,
                };
                if !self.pkg_images.contains(&k) {
                    if self.pkg_images.len() >= MODULE_PKG_IMAGES_MAX as usize {
                        self.pkg_images.clear();
                    }
                    self.pkg_images.push(k);
                    changed = true;
                }
            }
        }
        if changed {
            self.kernel.set_pkg_images(&self.pkg_images);
        }
    }

    /// What vouches for `f` ([`scan::vouched_by`]): a verified package
    /// (its content hashed, the package database's digest compared), DKMS's
    /// registry (the same content), nothing. Cached by the file's identity
    /// and change stamp.
    fn vouch(&mut self, f: &scan::TreeFile, inputs: &scan::Inputs<'_>) -> u32 {
        let dpkg = &self.dpkg;
        let rpm = self.rpm.as_ref().map(|(_, idx)| idx);
        self.cache.get(f, |f| {
            scan::vouched_by(f, inputs, |f| {
                let Some(path) = f.path.to_str() else {
                    return false;
                };
                if let Some(idx) = rpm {
                    let alias = path
                        .strip_prefix("/usr")
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("/usr{path}"));
                    return idx.get(path).or_else(|| idx.get(&alias)).is_some_and(
                        |(algo, want)| scan::rpm_digest_matches(&f.path, *algo, want),
                    );
                }
                let Ok(file) = std::fs::File::open(&f.path) else {
                    return false;
                };
                matches!(
                    dpkg.check(path, &file),
                    crate::execq::pkgtrust::PkgOutcome::Trusted { .. }
                )
            })
        })
    }

    /// One poll: look at the tree when something changed or it is time.
    fn round(&mut self) {
        let want = desired();
        let gen = self.kernel.write_gen();
        let stamp = db_stamp();
        let due = match &self.last {
            None => true,
            Some((at, g, d, s)) => {
                at.elapsed() >= FULL_EVERY || *g != gen || *d != want || *s != stamp
            }
        };
        if !due {
            return;
        }
        self.look(&want, stamp);
        self.last = Some((Instant::now(), gen, want, stamp));
    }

    fn look(&mut self, want: &Desired, stamp: Option<SystemTime>) {
        self.refresh_pkg_images();
        if rpm_host() && self.rpm.as_ref().is_none_or(|(s, _)| *s != stamp) {
            let rel = &self.release;
            let prefixes = vec![
                format!("{}/", self.tree.display()),
                format!("/lib/modules/{rel}/"),
                format!("/usr/lib/modules/{rel}/"),
            ];
            match scan::rpm_tree_digests(&prefixes) {
                Some(idx) => self.rpm = Some((stamp, idx)),
                None => warn!("module-load judge: rpm not asked — no rpm file vouched for"),
            }
        }
        let boot_sec = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| scan::boot_time(&s))
            .unwrap_or(i64::MAX);
        let (files, over) = scan::walk(&self.tree, MODULE_TRUST_MAX as usize);
        let registry = PathBuf::from("/var/lib/dkms");
        let release = self.release.clone();
        let tree = self.tree.clone();
        let inputs = inputs_of(
            want,
            &release,
            &tree,
            boot_sec,
            &registry,
            nn_linux::module_writes::history(),
        );
        let mut next: HashMap<InodeKey, ModuleTrust> = HashMap::with_capacity(files.len());
        let mut refused: Vec<(PathBuf, &'static str)> = Vec::new();
        let mut counts = [0usize; 5];
        for f in &files {
            let history = (f.facts.ctime_sec >= boot_sec)
                .then(|| self.kernel.history(f.key))
                .flatten();
            let mut vouch = |f: &scan::TreeFile| self.vouch(f, &inputs);
            match scan::classify(f, &inputs, history, &mut vouch) {
                Ok(flags) => {
                    for (i, bit) in [
                        trust_flag::PACKAGE,
                        trust_flag::DKMS,
                        trust_flag::PKG_WRITTEN,
                        trust_flag::OPT_OUT,
                        trust_flag::UNATTESTED,
                    ]
                    .iter()
                    .enumerate()
                    {
                        if flags & bit != 0 {
                            counts[i] += 1;
                        }
                    }
                    next.insert(
                        f.key,
                        ModuleTrust {
                            ctime_sec: f.facts.ctime_sec,
                            size: f.facts.size,
                            ctime_nsec: f.facts.ctime_nsec & common::module_judge::CTIME_NSEC_MASK,
                            flags,
                        },
                    );
                }
                Err(why) => refused.push((f.path.clone(), why)),
            }
        }
        // the map: what changed in, what left out
        let mut errors = 0usize;
        for (k, v) in &next {
            if self.mirror.get(k) != Some(v) && self.kernel.put(*k, *v).is_err() {
                errors += 1;
            }
        }
        for k in self.mirror.keys() {
            if !next.contains_key(k) {
                self.kernel.drop_key(*k);
            }
        }
        let keep: HashSet<InodeKey> = next.keys().copied().collect();
        self.cache.retain(&keep);
        let changed = self.mirror != next;
        self.mirror = next;
        // the mode, once the map is filled
        let m = if want.mode == mode::DENY && !self.deny_ok {
            mode::RECORD
        } else {
            want.mode
        };
        let first = self.armed.is_none();
        if self.armed != Some(m) {
            match self.kernel.set_mode(m) {
                Ok(()) => self.armed = Some(m),
                Err(e) => warn!(error = %e, "module-load judge: mode NOT written"),
            }
        }
        let summary = format!(
            "{}: {} module files trusted in {} ({} packaged, {} DKMS, {} written in a package \
             transaction since boot, {} by a signed opt-out, {} DKMS or akmods builds written \
             since boot outside one: let through, recorded), {} not{}{}",
            mode_name(self.armed.unwrap_or(mode::NOT_READY)),
            self.mirror.len(),
            self.tree.display(),
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            counts[4],
            refused.len(),
            if over > 0 {
                format!(", {over} past the map's capacity (untrusted)")
            } else {
                String::new()
            },
            if errors > 0 {
                format!(", {errors} map writes failed")
            } else {
                String::new()
            },
        );
        if first || changed {
            info!(summary = %summary, "module-load judge");
            for (p, why) in refused.iter().take(NAMED_MAX) {
                warn!(file = %p.display(), why, "module-load judge: a module file NOT trusted — a load of it is refused in the deny mode (a signed `module-allow <module>` lets it through)");
            }
        }
        set_state(summary);
    }
}

/// Start the controller on its own thread with the maps the load took.
/// `Err`: the judge cannot be fed (the start signs the degradation; the
/// kernel's mode stays "not armed": nothing judged, nothing refused).
pub fn start(kernel: Option<kernel::Kernel>) -> Result<std::thread::JoinHandle<()>, String> {
    let mut kernel =
        kernel.ok_or_else(|| "the judge's maps were not taken from the eBPF object".to_string())?;
    let release = release().ok_or_else(|| "the running kernel's release unreadable".to_string())?;
    let tree = std::fs::canonicalize(Path::new("/lib/modules").join(&release))
        .map_err(|e| format!("/lib/modules/{release}: {e}"))?;
    let root = std::fs::metadata(&tree).map_err(|e| format!("{}: {e}", tree.display()))?;
    kernel
        .set_tree(scan::key_of(&root))
        .map_err(|e| format!("{e:#}"))?;
    let deny_ok = offsets_resolved();
    if !deny_ok {
        crate::boot::degradation::report(
            "module_load",
            "the kernel's inode offsets (owner, change time) are not resolved: the module-load \
             judge trusts no file, its deny mode is not armed (the record mode instead)",
        );
    }
    let mut ctl = Controller {
        kernel,
        release,
        tree,
        deny_ok,
        mirror: HashMap::new(),
        pkg_images: Vec::new(),
        cache: scan::PackagedCache::default(),
        dpkg: crate::execq::pkgtrust::PackageTrust::new("/", false),
        rpm: None,
        last: None,
        armed: None,
    };
    set_state("starting".to_string());
    std::thread::Builder::new()
        .name("nn-module-trust".to_string())
        .spawn(move || {
            // the core's set, whoever starts it (it reads the package
            // database and the tree, writes the kernel's maps)
            nn_linux::caps::restore_core();
            loop {
                ctl.round();
                std::thread::sleep(POLL);
            }
        })
        .map_err(|e| format!("thread: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rule_policy::parse;

    /// The policy's mode for R018 is the judge's: `enforce` deny, any other
    /// mode record, no line the default; the `module-allow` lines only
    /// signed.
    #[test]
    fn the_policy_sets_the_judge() {
        assert_eq!(mode_of(&RulePolicy::builtin()), DEFAULT_MODE);
        assert_eq!(mode_of(&parse("enforce R018\n").unwrap()), mode::DENY);
        // the coordinator's matrix: an unattested DKMS build let through
        // (recorded) by every policy but `enforce R018`
        assert!(unattested_of(&RulePolicy::builtin()));
        assert!(!unattested_of(&parse("enforce R018\n").unwrap()));
        for m in ["alert", "audit", "off"] {
            assert!(
                unattested_of(&parse(&format!("{m} R018\n")).unwrap()),
                "{m}"
            );
        }
        assert!(unattested_of(&parse("enforce R011\n").unwrap()));
        for m in ["alert", "audit", "off"] {
            assert_eq!(
                mode_of(&parse(&format!("{m} R018\n")).unwrap()),
                mode::RECORD,
                "{m}"
            );
        }
        let p = parse("alert R018\nmodule-allow nvidia-drm\n").unwrap();
        let withheld = apply_policy(&p, false).expect("withheld, signed degraded");
        assert!(
            withheld.contains("1 module-allow line(s) NOT honoured"),
            "{withheld}"
        );
        assert_eq!(
            desired(),
            Desired {
                mode: mode::RECORD,
                opt_outs: BTreeSet::new(),
                unattested: true,
            }
        );
        assert!(apply_policy(&p, true).is_none());
        assert_eq!(
            desired().opt_outs,
            ["nvidia_drm".to_string()].into_iter().collect()
        );
        assert!(apply_policy(&parse("enforce R018\n").unwrap(), true).is_none());
        assert_eq!(
            desired(),
            Desired {
                mode: mode::DENY,
                opt_outs: BTreeSet::new(),
                unattested: false,
            }
        );
        // what a look classifies with
        let enforced = desired();
        let tree = Path::new("/lib/modules/6.8.0");
        let reg = Path::new("/var/lib/dkms");
        let i = inputs_of(&enforced, "6.8.0", tree, 7, reg, None);
        assert!(!i.unattested);
        // no history (none attached, or not reliable): it covers no write
        assert_eq!(i.history_since, (i64::MAX, 0));
        let h = nn_linux::module_writes::History {
            since: Some((1_762_400_000, 7)),
            note: None,
        };
        assert_eq!(
            inputs_of(&enforced, "6.8.0", tree, 7, reg, Some(h.clone())).history_since,
            (1_762_400_000, 7)
        );
        let unreliable = nn_linux::module_writes::History { since: None, ..h };
        assert_eq!(history_since(Some(unreliable)), (i64::MAX, 0));
        assert_eq!(
            (i.release, i.tree, i.boot_sec, i.dkms_registry),
            ("6.8.0", tree, 7, reg)
        );
        assert!(apply_policy(&RulePolicy::builtin(), true).is_none());
        assert_eq!(desired(), Desired::default());
        let builtin = desired();
        assert!(inputs_of(&builtin, "6.8.0", tree, 7, reg, None).unattested);
        let named = parse("module-allow zfs\n").unwrap();
        assert!(apply_policy(&named, true).is_none());
        let with = desired();
        assert!(inputs_of(&with, "6.8.0", tree, 7, reg, None)
            .opt_outs
            .contains("zfs"));
        assert!(apply_policy(&RulePolicy::builtin(), true).is_none());
        assert_eq!(mode_name(mode::DENY), "deny");
        assert_eq!(mode_name(mode::NOT_READY), "not armed");
    }
}
