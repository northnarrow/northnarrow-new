//! Lot 279: what an exec of a kernel-module tool LOADS, judged before R011
//! decides — not the tool's name.
//!
//! R011 killed every exec of `insmod`, `modprobe` or `kmod` that no
//! package-manager actor ran and no kernel thread asked for: the `modprobe`
//! of rootful podman's netfilter modules among them (lot 275's lab: W5 rc
//! 137 on Ubuntu 22.04). An exec is now RECORDED (High, T1547.006, no
//! kill) when what it loads is vouched for, and KILLED as before otherwise:
//!
//! | The exec | R011 |
//! |---|---|
//! | the system's tool (a file of `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) asked for module NAMES, each resolved as kmod does to files of `/lib/modules/$(uname -r)/` that a package installed, DKMS built, or (no package database) the running kernel's `modules.order` lists — none changed since the package database's last change (DKMS: since its registry's; the kernel's tree: since the boot), each uncompressed one signed while the kernel enforces signatures | record |
//! | a query that inserts nothing: `-r`, `-n`, `-D`, `-c`, `-R`, `--show-*`, `-V`, `-h`; `kmod list` / `static-nodes`; kmod run as `lsmod`, `rmmod`, `modinfo`, `depmod`; a usage error | record |
//! | `insmod` of any file; `modprobe` of a path or a `.ko*` name | kill |
//! | `-C`, `-d`, `-S` (the caller's configuration, tree root or kernel version), `-f` / `--force-*` | kill |
//! | a name no index of the running kernel's tree resolves; a file outside it, a link (or behind a directory linked out of it), unowned, changed after its owner's last change, unsigned under enforcement | kill |
//! | a copy of the tool elsewhere, another program named like it, a program of a filesystem the host's mount table does not show, an argv the kernel did not read whole, an option the tool would refuse | kill |
//!
//! **Resolution** follows libkmod's lookup order (`kmod_module_new_from_lookup`):
//! the aliases of the configuration (`modprobe.d`: `/etc`, `/run`,
//! `/usr/local/lib`, `/lib`, `/usr/lib`; a file of an earlier directory
//! hides one of the same name), then the module names of `modules.dep`,
//! then `modules.symbols`, `modules.alias` (fnmatch patterns), and the
//! built-in modules: by name (`modules.builtin`) and by alias — the
//! `alias` entries of `modules.builtin.modinfo`, from which depmod writes
//! the `modules.builtin.alias.bin` kmod reads (kmod 27+,
//! `kmod_lookup_alias_from_kernel_builtin_file`; depmod writes no text
//! form of it). A request every name of which is built in inserts nothing:
//! recorded as a query. Each module's dependencies are `modules.dep`'s (the closure);
//! its soft dependencies (`softdep` of the configuration and of
//! `modules.softdep`) are resolved the same way and judged too; a soft
//! dependency nothing resolves is skipped, as kmod skips it. Names are
//! normalised as kmod does (`-` is `_` outside a `[...]` class).
//!
//! **What is spoofable, and why the result stays fail-closed.** The
//! caller chooses the `argv`, but the tool acts on the same one (the sensor
//! reads it at the exec, before the new program runs; rewriting it later
//! changes only `/proc/<pid>/cmdline`). The tool also reads what this does
//! not see: `MODPROBE_OPTIONS` (options prepended from the environment —
//! `-d /tmp/root` there loads a file of the caller's tree) and the binary
//! indexes (`modules.dep.bin`, `modules.alias.bin`), which depmod writes
//! beside the text ones read here and which a root can edit apart from them.
//! A load either redirects is still the kernel's to report: R018 judges
//! the file the kernel reads (`kernel_read_file`, its path from the dentry)
//! and kills a load from outside the module directories, or of a file there
//! that no package installed, whatever the loader is called and whatever
//! R011 decided at the exec — as for a direct `finit_module(2)`, which never
//! needed a module tool. The time checks compare `max(mtime, ctime)`: a
//! caller sets the mtime (`touch -d`), not the ctime. What stays open, and
//! where it is covered: a packaged module file overwritten in place and
//! then followed by any package transaction passes the time check (the
//! write is FIM-008's, the kernel's signature check rejects it when
//! enforced); a compressed image's signature is inside its compressed
//! stream, which the agent does not decompress (the kernel verifies it when
//! it enforces signatures, refusing the load).
//!
//! **A module copied into `/lib/modules/$(uname -r)/` and `modprobe`d**
//! (after `depmod`): resolved, but no package lists the file and DKMS did
//! not build it — killed, as before (and its load, if it lands first, is
//! R018's kill of an unowned module by an unexpected loader). Without
//! `depmod` the name resolves to nothing: killed.
//!
//! **Where it runs.** The exec pump asks ([`ModuleRequests::refresh`]: the
//! module tree's indexes, the configuration, a few `stat`s and the package
//! database on its own thread, for the execs of a module tool only) and
//! keeps the answer per exec ([`REQUESTS`]); R011 judges the exec on it
//! ([`ModuleRequests::of`]) — no file read on the decision's thread. An
//! exec no pump asked about (the replay, the tests) is assessed there. The
//! exec pump runs no process: on an RPM host a module file is the
//! package's once the module-load pump's `rpm -qf` said so (a load of it
//! since the start); until then it is judged by the running kernel's
//! `modules.order` and the boot ([`ModuleOwners::without_a_process`]) —
//! an out-of-tree module there is killed until its first load is seen.

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use nn_model::Event;
use parking_lot::Mutex;

use super::kmod_invocation::{self, Invocation};
use super::module_provenance::{ModuleOwners, Provenance};
use crate::decision::host::DecisionHost;

/// Kernel-module load/manage tool comms (design §7.1).
pub const KMOD_TOOLS: &[&str] = &["insmod", "modprobe", "kmod"];

/// What an exec of a module tool loads, as R011 judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    /// It inserts no module (what it does instead).
    LoadsNothing(String),
    /// Every module it would load is vouched for (which, and by what).
    Vouched(String),
    /// Not vouched for (why): R011's kill.
    NotVouched(String),
}

impl Assessment {
    /// R011 records it, no kill.
    pub fn records(&self) -> bool {
        !matches!(self, Assessment::NotVouched(_))
    }
}

/// The assessments the exec pump made, per (host root, pid, exec time) —
/// R011 judges each exec on its own. Bounded ([`REQUEST_KEYS`]: full, it
/// starts again; an exec whose answer was dropped is assessed again where
/// it is judged).
static REQUESTS: LazyLock<Mutex<HashMap<ExecKey, Assessment>>> = LazyLock::new(Default::default);
/// (host root, pid, the exec's time).
type ExecKey = (PathBuf, u32, u64);
/// The execs [`REQUESTS`] keeps answers for at most.
pub const REQUEST_KEYS: usize = 1024;

/// The appended-signature marker of a module image (`MODULE_SIG_STRING`).
const SIG_MARKER: &[u8] = b"~Module signature appended~\n";

/// The largest index or configuration file read (a larger one is not
/// read: what it resolves is not vouched for).
const MAX_INDEX_BYTES: u64 = 32 << 20;

/// How many modules (names, aliases' targets and soft dependencies) one
/// exec is judged on at most; past it, not vouched for.
const MAX_TARGETS: usize = 64;

/// The configuration directories, in libkmod's order (`default_config_paths`
/// and kmod 31's `/usr/lib/modprobe.d`).
const CONFIG_DIRS: &[&str] = &[
    "etc/modprobe.d",
    "run/modprobe.d",
    "usr/local/lib/modprobe.d",
    "lib/modprobe.d",
    "usr/lib/modprobe.d",
];

/// The indexes depmod writes in a module tree that this reads.
const INDEXES: &[&str] = &[
    "modules.dep",
    "modules.alias",
    "modules.symbols",
    "modules.builtin",
    "modules.builtin.modinfo",
    "modules.softdep",
    "modules.order",
];

/// R08b: `H` is the host whose package database [`ModuleOwners`] asks and
/// whose work [`Self::of`] keeps off the async runtime.
pub struct ModuleRequests<H: DecisionHost> {
    /// `/` in production; a fixture tree in tests.
    root: PathBuf,
    owners: ModuleOwners<H>,
    /// The running kernel's module tree, read again when an index changes.
    tree: Mutex<Option<ModuleTree>>,
    host: PhantomData<fn() -> H>,
}

impl<H: DecisionHost> Default for ModuleRequests<H> {
    fn default() -> Self {
        Self::new(H::HOST_ROOT)
    }
}

impl<H: DecisionHost> ModuleRequests<H> {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            owners: ModuleOwners::new(root.clone()),
            root,
            tree: Mutex::new(None),
            host: PhantomData,
        }
    }

    /// The exec pump's call, for every exec it reads: an exec of a module
    /// tool is assessed now, its package ownership asked fresh, and the
    /// answer kept for R011 ([`Self::of`]). `None` for any other event.
    pub fn refresh(&self, event: &Event) -> Option<Assessment> {
        let Event::ProcessSpawn {
            pid,
            comm,
            timestamp_ns,
            ..
        } = event
        else {
            return None;
        };
        if !KMOD_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        let a = self.assess(event, true);
        let mut kept = REQUESTS.lock();
        if kept.len() >= REQUEST_KEYS {
            kept.clear();
        }
        kept.insert((self.root.clone(), *pid, *timestamp_ns), a.clone());
        Some(a)
    }

    /// What `event` (an exec of a module tool) loads: the answer the exec
    /// pump kept, else assessed here off the runtime's worker.
    pub fn of(&self, event: &Event) -> Assessment {
        if let Event::ProcessSpawn {
            pid, timestamp_ns, ..
        } = event
        {
            if let Some(a) = REQUESTS
                .lock()
                .get(&(self.root.clone(), *pid, *timestamp_ns))
            {
                return a.clone();
            }
        }
        H::off_the_runtime(|| self.assess(event, false))
    }

    /// The assessment of `event`; `fresh`: ask the package database now
    /// (the pump) rather than read its last answer.
    fn assess(&self, event: &Event, fresh: bool) -> Assessment {
        let Event::ProcessSpawn {
            filename,
            exe,
            argv,
            argv_truncated,
            ..
        } = event
        else {
            return Assessment::NotVouched("not an exec".to_string());
        };
        if argv.is_empty() {
            return Assessment::NotVouched(
                "its argv was not read by the kernel: no argument was checked".to_string(),
            );
        }
        if *argv_truncated {
            return Assessment::NotVouched(format!(
                "its argv was cut at {} bytes: arguments past the cut were not seen",
                common::wire::ARGV_LEN - 1
            ));
        }
        // the kernel named a file of a filesystem this mount namespace does
        // not show (another namespace's root): not the host's tool, and its
        // module tree is not the one read here
        if !exe.path.is_empty() && exe.root != (0, 0) {
            return Assessment::NotVouched(format!(
                "the program ({}) is in a filesystem the host's mount table does not show",
                exe.path
            ));
        }
        let tool = match kmod_invocation::tool_of(exe.path_or(filename), argv) {
            Ok(t) => t,
            Err(why) => return Assessment::NotVouched(why),
        };
        match kmod_invocation::parse(tool, argv) {
            Invocation::LoadsNothing(what) => Assessment::LoadsNothing(what),
            Invocation::Refused(why) => Assessment::NotVouched(why),
            Invocation::Modules(names) => match self.judge(&names, fresh) {
                // every name built into the running kernel: modprobe
                // inserts nothing (kmod: success, no load)
                Ok((what, true)) => Assessment::LoadsNothing(format!(
                    "modprobe of built-in modules, nothing to insert: {what}"
                )),
                Ok((what, false)) => Assessment::Vouched(what),
                Err(why) => Assessment::NotVouched(why),
            },
        }
    }

    /// Every module `names` load, resolved and vouched for — or why not.
    fn judge(&self, names: &[String], fresh: bool) -> Result<(String, bool), String> {
        let facts = HostFacts::read(&self.root)?;
        let mut cached = self.tree.lock();
        let tree = ModuleTree::current(&self.root, &facts.release, &mut cached)?;
        let config = Config::read(&self.root);
        let mut parts = Vec::new();
        let mut judged = HashSet::new();
        let mut all_builtin = true;
        for name in names {
            let targets = resolve_all(tree, &config, name)?;
            all_builtin &= targets.iter().all(|t| matches!(t, Target::Builtin(_)));
            let mut what = Vec::new();
            for t in &targets {
                match t {
                    Target::Builtin(m) => what.push(format!("{m} (built in: nothing to load)")),
                    Target::File {
                        name: m,
                        path,
                        deps,
                    } => {
                        let mut kinds = Vec::new();
                        for p in std::iter::once(path).chain(deps.iter()) {
                            if !judged.insert(p.clone()) {
                                continue;
                            }
                            let kind = self
                                .vouch(tree, &facts, p, fresh)
                                .map_err(|why| format!("modprobe {name}: {p}: {why}"))?;
                            if !kinds.contains(&kind) {
                                kinds.push(kind);
                            }
                        }
                        let deps = match deps.len() {
                            0 => String::new(),
                            1 => " and 1 dependency".to_string(),
                            n => format!(" and {n} dependencies"),
                        };
                        what.push(format!(
                            "{m}: {path}{deps}, {}",
                            if kinds.is_empty() {
                                "judged above".to_string()
                            } else {
                                kinds.join(", ")
                            }
                        ));
                    }
                }
            }
            parts.push(format!("{name} → {}", what.join("; ")));
        }
        Ok((
            format!(
                "{} (the running kernel {}'s tree)",
                parts.join(" | "),
                facts.release
            ),
            all_builtin,
        ))
    }

    /// Why the module file `path` (as `modules.dep` names it) may be loaded:
    /// who installed it, and that it is unchanged since — or why not.
    fn vouch(
        &self,
        tree: &ModuleTree,
        facts: &HostFacts,
        path: &str,
        fresh: bool,
    ) -> Result<&'static str, String> {
        let dir = format!("/lib/modules/{}/", facts.release);
        let logical = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{dir}{path}")
        };
        let inside = logical
            .strip_prefix(&dir)
            .or_else(|| logical.strip_prefix(&format!("/usr{dir}")));
        let Some(rel) = inside else {
            return Err(format!("outside the running kernel's tree {dir}"));
        };
        if rel
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err("its path leaves the module tree".to_string());
        }
        let on_disk = self.root.join(logical.trim_start_matches('/'));
        let meta =
            std::fs::symlink_metadata(&on_disk).map_err(|e| format!("cannot be read ({e})"))?;
        if !meta.file_type().is_file() {
            return Err("not a regular file (a link or another kind)".to_string());
        }
        // no directory of the tree on the way is a link elsewhere: the file
        // is where its path in the tree says (a merged /usr's `/lib` link
        // is the tree's own, resolved on both sides)
        let tree_dir = self.root.join(dir.trim_start_matches('/'));
        let real = std::fs::canonicalize(&on_disk).ok();
        let expected = std::fs::canonicalize(&tree_dir).ok().map(|d| d.join(rel));
        if real.is_none() || real != expected {
            return Err(
                "a directory on its path is a link out of the running kernel's tree".to_string(),
            );
        }
        // the exec pump runs no process (an RPM host's `rpm -qf` is the
        // module-load pump's); the decision's own assessment asks as R018
        let provenance = if fresh {
            self.owners.without_a_process(&logical)
        } else {
            self.owners.of(&logical)
        };
        let (kind, since, owner) = match provenance {
            Provenance::Package => (
                "installed by a package, unchanged since the package database's last change",
                facts.package_db,
                "the package database's last change",
            ),
            Provenance::Dkms => (
                "built by DKMS, unchanged since its registry's last change",
                facts
                    .package_db
                    .max(newest_under::<H>(&self.root.join("var/lib/dkms"), 6)),
                "DKMS's registry's last change",
            ),
            Provenance::Unknown if tree.order.contains(without_compression(rel)) => (
                "in the running kernel's own tree (its modules.order; no package database), \
                 unchanged since the boot",
                facts.boot,
                "the boot",
            ),
            Provenance::Unknown => {
                return Err(
                    "no package database to ask, and the running kernel's modules.order does \
                     not list it"
                        .to_string(),
                )
            }
            Provenance::Unowned => {
                return Err(
                    "in the module tree, but no package installed it and DKMS did not \
                     build it: copied or built there by hand"
                        .to_string(),
                )
            }
        };
        let since = since.ok_or_else(|| {
            format!("{owner} could not be read: nothing to compare its change with")
        })?;
        let changed = changed_at::<H>(&meta).ok_or("its change time could not be read")?;
        if changed > since {
            return Err(format!(
                "changed at {} (mtime/ctime), after {owner} at {}",
                unix_secs(changed),
                unix_secs(since)
            ));
        }
        if facts.sig_enforced && logical.ends_with(".ko") && !signed(&on_disk) {
            return Err(
                "no appended signature while the kernel enforces module signatures".to_string(),
            );
        }
        Ok(kind)
    }
}

/// What the judgement reads of the running kernel and the host.
struct HostFacts {
    release: String,
    /// The package database's last change (dpkg's status file, rpm's
    /// database files).
    package_db: Option<SystemTime>,
    boot: Option<SystemTime>,
    /// `module.sig_enforce`, or lockdown (integrity, confidentiality), which
    /// refuses an unsigned module whatever `sig_enforce` says.
    sig_enforced: bool,
}

impl HostFacts {
    fn read(root: &Path) -> Result<Self, String> {
        let release = std::fs::read_to_string(root.join("proc/sys/kernel/osrelease"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.contains('/') && s != "." && s != "..")
            .ok_or("the running kernel's release could not be read")?;
        let mtime = |p: &str| {
            std::fs::metadata(root.join(p))
                .and_then(|m| m.modified())
                .ok()
        };
        let package_db = [
            "var/lib/dpkg/status",
            "var/lib/rpm/rpmdb.sqlite",
            "var/lib/rpm/Packages",
            "var/lib/rpm/Packages.db",
            "usr/lib/sysimage/rpm/rpmdb.sqlite",
            "usr/lib/sysimage/rpm/Packages.db",
        ]
        .iter()
        .filter_map(|p| mtime(p))
        .max();
        let boot = std::fs::read_to_string(root.join("proc/stat"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("btime "))
                    .and_then(|v| v.trim().parse::<u64>().ok())
            })
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s));
        let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap_or_default();
        let sig_enforced = read("sys/module/module/parameters/sig_enforce").trim() == "Y" || {
            let l = read("sys/kernel/security/lockdown");
            l.contains("[integrity]") || l.contains("[confidentiality]")
        };
        Ok(Self {
            release,
            package_db,
            boot,
            sig_enforced,
        })
    }
}

/// The indexes of the running kernel's module tree.
#[derive(Default)]
struct ModuleTree {
    release: String,
    /// `(mtime, length)` of each of [`INDEXES`] when read.
    stamps: Vec<Option<(SystemTime, u64)>>,
    /// Module name → its file and its dependencies' (as `modules.dep`
    /// names them, relative to the tree).
    deps: HashMap<String, (String, Vec<String>)>,
    /// Built-in module names.
    builtin: HashSet<String>,
    /// (normalised pattern, module name) of `modules.symbols`, then
    /// `modules.alias`.
    aliases: Vec<(String, String)>,
    /// The `alias` entries of `modules.builtin.modinfo`: (normalised
    /// pattern, built-in module).
    builtin_aliases: Vec<(String, String)>,
    /// `modules.softdep`: (module pattern, soft dependencies).
    softdeps: Vec<(String, Vec<String>)>,
    /// `modules.order`: the kernel's own modules, without a compression
    /// suffix.
    order: HashSet<String>,
}

impl ModuleTree {
    /// The tree of `release`, read again when one of its indexes changed.
    fn current<'a>(
        root: &Path,
        release: &str,
        cached: &'a mut Option<ModuleTree>,
    ) -> Result<&'a ModuleTree, String> {
        let dir = root.join("lib/modules").join(release);
        let stamps: Vec<_> = INDEXES
            .iter()
            .map(|f| {
                std::fs::metadata(dir.join(f))
                    .ok()
                    .and_then(|m| Some((m.modified().ok()?, m.len())))
            })
            .collect();
        let stale = cached
            .as_ref()
            .is_none_or(|t| t.release != release || t.stamps != stamps);
        if stale {
            *cached = Some(Self::read(&dir, release, stamps)?);
        }
        cached
            .as_ref()
            .ok_or_else(|| "the module tree could not be read".to_string())
    }

    fn read(
        dir: &Path,
        release: &str,
        stamps: Vec<Option<(SystemTime, u64)>>,
    ) -> Result<Self, String> {
        let dep = read_bounded(&dir.join("modules.dep")).ok_or_else(|| {
            format!("the running kernel's modules.dep (/lib/modules/{release}) could not be read")
        })?;
        let mut t = ModuleTree {
            release: release.to_string(),
            stamps,
            ..Default::default()
        };
        for line in dep.lines() {
            let Some((path, deps)) = line.split_once(':') else {
                continue;
            };
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            let deps = deps.split_whitespace().map(String::from).collect();
            t.deps
                .entry(modname(path))
                .or_insert_with(|| (path.to_string(), deps));
        }
        let lines = |f: &str| read_bounded(&dir.join(f)).unwrap_or_default();
        for f in ["modules.symbols", "modules.alias"] {
            t.aliases.extend(alias_lines(&lines(f)));
        }
        t.builtin_aliases = builtin_modinfo_aliases(&lines("modules.builtin.modinfo"));
        t.builtin = lines("modules.builtin")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(modname)
            .collect();
        t.softdeps = softdep_lines(&lines("modules.softdep"));
        t.order = lines("modules.order")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| without_compression(l).to_string())
            .collect();
        Ok(t)
    }
}

/// The configuration's aliases and soft dependencies.
#[derive(Default)]
struct Config {
    aliases: Vec<(String, String)>,
    softdeps: Vec<(String, Vec<String>)>,
}

impl Config {
    fn read(root: &Path) -> Self {
        let mut seen = HashSet::new();
        let mut files = Vec::new();
        for d in CONFIG_DIRS {
            let Ok(entries) = std::fs::read_dir(root.join(d)) else {
                continue;
            };
            let mut names: Vec<_> = entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".conf"))
                .collect();
            names.sort();
            for n in names {
                if files.len() < 256 && seen.insert(n.clone()) {
                    files.push(root.join(d).join(n));
                }
            }
        }
        files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        let mut c = Config::default();
        for f in files {
            let text = read_bounded(&f).unwrap_or_default();
            // a trailing backslash continues the line
            let joined = text.replace("\\\n", " ");
            // a comment (`#` first) is no `alias` or `softdep` line
            for line in joined.lines() {
                let mut w = line.split_whitespace();
                match w.next() {
                    Some("alias") => {
                        if let (Some(a), Some(m)) = (w.next(), w.next()) {
                            if let (Some(a), Some(m)) = (normalize(a), normalize(m)) {
                                c.aliases.push((a, m));
                            }
                        }
                    }
                    Some("softdep") => c.softdeps.extend(softdep_lines(line)),
                    _ => {}
                }
            }
        }
        c
    }
}

/// What a name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Builtin(String),
    File {
        name: String,
        path: String,
        deps: Vec<String>,
    },
}

/// `name` and its soft dependencies (closure), resolved.
fn resolve_all(tree: &ModuleTree, config: &Config, name: &str) -> Result<Vec<Target>, String> {
    let mut out: Vec<Target> = Vec::new();
    let mut seen = HashSet::new();
    let mut queue: Vec<(String, bool)> = vec![(name.to_string(), true)];
    while let Some((n, required)) = queue.pop() {
        let found = resolve(tree, config, &n);
        let targets = match (found, required) {
            (Ok(t), _) => t,
            (Err(why), true) => return Err(format!("modprobe {n}: {why}")),
            // kmod skips a soft dependency it does not find: no load
            (Err(_), false) => continue,
        };
        for t in targets {
            let m = match &t {
                Target::Builtin(m) | Target::File { name: m, .. } => m.clone(),
            };
            if !seen.insert(m.clone()) {
                continue;
            }
            if out.len() >= MAX_TARGETS {
                return Err(format!(
                    "modprobe {name}: more than {MAX_TARGETS} modules to judge"
                ));
            }
            for (pat, soft) in config.softdeps.iter().chain(tree.softdeps.iter()) {
                if fnmatch(pat.as_bytes(), m.as_bytes()) {
                    queue.extend(soft.iter().map(|s| (s.clone(), false)));
                }
            }
            out.push(t);
        }
    }
    Ok(out)
}

/// What libkmod's lookup finds for `name` (`kmod_module_new_from_lookup`).
fn resolve(tree: &ModuleTree, config: &Config, name: &str) -> Result<Vec<Target>, String> {
    let n = normalize(name).ok_or_else(|| format!("'{name}' is no valid module name"))?;
    let by_name = |m: &str| -> Option<Target> {
        if let Some((path, deps)) = tree.deps.get(m) {
            return Some(Target::File {
                name: m.to_string(),
                path: path.clone(),
                deps: deps.clone(),
            });
        }
        tree.builtin
            .contains(m)
            .then(|| Target::Builtin(m.to_string()))
    };
    let matches = |table: &[(String, String)]| -> Vec<String> {
        table
            .iter()
            .filter(|(pat, _)| fnmatch(pat.as_bytes(), n.as_bytes()))
            .map(|(_, m)| m.clone())
            .collect()
    };
    let targets_of = |mods: Vec<String>, via: &str| -> Result<Vec<Target>, String> {
        mods.iter()
            .map(|m| {
                by_name(m).ok_or_else(|| {
                    format!(
                        "{via} names module '{m}', which the running kernel's tree does not hold"
                    )
                })
            })
            .collect()
    };
    let configured = matches(&config.aliases);
    if !configured.is_empty() {
        return targets_of(configured, "an alias of the configuration");
    }
    if let Some((path, deps)) = tree.deps.get(&n) {
        return Ok(vec![Target::File {
            name: n,
            path: path.clone(),
            deps: deps.clone(),
        }]);
    }
    let aliased = matches(&tree.aliases);
    if !aliased.is_empty() {
        return targets_of(aliased, "an alias of the module tree");
    }
    if tree.builtin.contains(&n) {
        return Ok(vec![Target::Builtin(n)]);
    }
    let builtin: Vec<Target> = matches(&tree.builtin_aliases)
        .into_iter()
        .map(Target::Builtin)
        .collect();
    if !builtin.is_empty() {
        return Ok(builtin);
    }
    Err("no module of the running kernel's tree is named or aliased so".to_string())
}

/// `alias <pattern> <module>` lines, normalised.
fn alias_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "alias").then_some(())?;
            Some((normalize(w.next()?)?, normalize(w.next()?)?))
        })
        .collect()
}

/// The `alias` entries of `modules.builtin.modinfo` (`modname.key=value`,
/// each ended by a NUL), as depmod reads them for `modules.builtin.alias.bin`.
fn builtin_modinfo_aliases(text: &str) -> Vec<(String, String)> {
    text.split('\0')
        .filter_map(|e| {
            let (module, kv) = e.split_once('.')?;
            let value = kv.strip_prefix("alias=")?;
            Some((normalize(value)?, normalize(module)?))
        })
        .collect()
}

/// `softdep <module> pre: <a> … post: <b> …` lines: the module and every
/// soft dependency.
fn softdep_lines(text: &str) -> Vec<(String, Vec<String>)> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "softdep").then_some(())?;
            let m = normalize(w.next()?)?;
            let soft = w
                .filter(|t| *t != "pre:" && *t != "post:")
                .filter_map(normalize)
                .collect();
            Some((m, soft))
        })
        .collect()
}

/// libkmod's `alias_normalize`: `-` is `_` outside a `[...]` class; `None`
/// for a name the tool refuses (an unbalanced class).
fn normalize(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        match c {
            '-' => out.push('_'),
            ']' => return None,
            '[' => {
                out.push('[');
                loop {
                    let c = chars.next()?;
                    out.push(c);
                    if c == ']' {
                        break;
                    }
                }
            }
            c => out.push(c),
        }
    }
    (!out.is_empty()).then_some(out)
}

/// libkmod's `path_to_modname`: the basename up to its first `.`, `-` as
/// `_`.
fn modname(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.split('.').next().unwrap_or(base).replace('-', "_")
}

/// `x.ko.zst` → `x.ko` (`modules.order` names the image as built).
fn without_compression(path: &str) -> &str {
    for s in [".xz", ".zst", ".gz"] {
        if let Some(p) = path.strip_suffix(s) {
            return p;
        }
    }
    path
}

/// `fnmatch(3)` without flags: `*`, `?`, `[...]` (`!` or `^` negates,
/// ranges), `\` escapes.
fn fnmatch(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while i < s.len() {
        if p < pat.len() {
            match pat[p] {
                b'*' => {
                    star = Some((p, i));
                    p += 1;
                    continue;
                }
                b'?' => {
                    p += 1;
                    i += 1;
                    continue;
                }
                b'[' => {
                    if let Some((hit, next)) = class(pat, p, s[i]) {
                        if hit {
                            p = next;
                            i += 1;
                            continue;
                        }
                    } else if s[i] == b'[' {
                        p += 1;
                        i += 1;
                        continue;
                    }
                }
                b'\\' if p + 1 < pat.len() => {
                    if pat[p + 1] == s[i] {
                        p += 2;
                        i += 1;
                        continue;
                    }
                }
                c => {
                    if c == s[i] {
                        p += 1;
                        i += 1;
                        continue;
                    }
                }
            }
        }
        match star {
            Some((sp, si)) => {
                p = sp + 1;
                i = si + 1;
                star = Some((sp, si + 1));
            }
            None => return false,
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// The bracket expression at `pat[at]` (`[`) against `c`: whether it
/// matches and the index past it; `None` when it is not closed (then `[`
/// is a plain character).
fn class(pat: &[u8], at: usize, c: u8) -> Option<(bool, usize)> {
    let mut j = at + 1;
    let negate = matches!(pat.get(j), Some(b'!') | Some(b'^'));
    if negate {
        j += 1;
    }
    let mut hit = false;
    let mut first = true;
    while j < pat.len() {
        let lo = pat[j];
        if lo == b']' && !first {
            return Some((hit != negate, j + 1));
        }
        first = false;
        if j + 2 < pat.len() && pat[j + 1] == b'-' && pat[j + 2] != b']' {
            hit |= (lo..=pat[j + 2]).contains(&c);
            j += 3;
        } else {
            hit |= lo == c;
            j += 1;
        }
    }
    None
}

/// A file of at most [`MAX_INDEX_BYTES`], as text.
fn read_bounded(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_INDEX_BYTES {
        return None;
    }
    std::fs::read(path)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The last change of a file's content or inode: `max(mtime, ctime)` — a
/// caller sets the mtime, not the ctime (the host's,
/// [`DecisionHost::inode_changed`]).
fn changed_at<H: DecisionHost>(meta: &std::fs::Metadata) -> Option<SystemTime> {
    meta.modified().ok().max(H::inode_changed(meta))
}

/// The newest change under `dir`, `depth` levels down at most (4,096
/// entries at most).
fn newest_under<H: DecisionHost>(dir: &Path, depth: usize) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    let mut stack = vec![(dir.to_path_buf(), depth)];
    let mut seen = 0usize;
    while let Some((d, left)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            seen += 1;
            if seen > 4096 {
                return newest;
            }
            let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            newest = newest.max(changed_at::<H>(&meta));
            if meta.is_dir() && left > 1 {
                stack.push((e.path(), left - 1));
            }
        }
    }
    newest
}

/// The image at `path` ends with the appended-signature marker.
fn signed(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let n = SIG_MARKER.len() as i64;
    if f.seek(SeekFrom::End(-n)).is_err() {
        return false;
    }
    let mut tail = vec![0u8; SIG_MARKER.len()];
    f.read_exact(&mut tail).is_ok() && tail == SIG_MARKER
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A host tree for the tests: the running kernel's release and boot, its
/// module tree and indexes, dpkg's lists and status.
#[cfg(test)]
pub(crate) mod fixture {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use nn_model::Event;

    pub const RELEASE: &str = "6.8.0-1-generic";

    pub struct HostTree {
        pub dir: tempfile::TempDir,
    }

    impl HostTree {
        /// A dpkg host booted an hour ago, its package database changed
        /// after every file the tests write (an hour from now).
        pub fn new() -> Self {
            let t = HostTree {
                dir: tempfile::TempDir::new().unwrap(),
            };
            t.write("proc/sys/kernel/osrelease", &format!("{RELEASE}\n"));
            t.booted(SystemTime::now() - Duration::from_secs(3600));
            t.write("var/lib/dpkg/status", "Package: linux-modules\n");
            std::fs::create_dir_all(t.dir.path().join("var/lib/dpkg/info")).unwrap();
            t.write(&format!("lib/modules/{RELEASE}/modules.dep"), "");
            t.db_changed(SystemTime::now() + Duration::from_secs(3600));
            t
        }

        pub fn root(&self) -> &Path {
            self.dir.path()
        }

        pub fn path(&self, rel: &str) -> PathBuf {
            self.dir.path().join(rel)
        }

        pub fn write(&self, rel: &str, text: &str) {
            let p = self.path(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }

        pub fn append(&self, rel: &str, text: &str) {
            use std::io::Write;
            let p = self.path(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .unwrap();
            f.write_all(text.as_bytes()).unwrap();
        }

        /// `rel` (relative to the module tree) written, signed or not, and
        /// listed in modules.dep with `deps`.
        pub fn module(&self, rel: &str, deps: &[&str], signed: bool) -> &Self {
            // longer than the marker either way: its absence is read, not
            // a short file's
            let body: &[u8] = if signed {
                b"\x7fELF........................~Module signature appended~\n"
            } else {
                b"\x7fELF.........................................................."
            };
            let p = self.path(&format!("lib/modules/{RELEASE}/{rel}"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
            self.append(
                &format!("lib/modules/{RELEASE}/modules.dep"),
                &format!("{rel}: {}\n", deps.join(" ")),
            );
            self
        }

        /// A package lists these module files (relative to the tree).
        pub fn packaged(&self, pkg: &str, rels: &[&str]) -> &Self {
            let list: String = rels
                .iter()
                .map(|r| format!("/lib/modules/{RELEASE}/{r}\n"))
                .collect();
            self.write(&format!("var/lib/dpkg/info/{pkg}.list"), &list);
            // dpkg rewrites its status at every transaction
            self.db_changed(SystemTime::now() + Duration::from_secs(3600));
            self
        }

        pub fn index(&self, name: &str, text: &str) -> &Self {
            self.append(&format!("lib/modules/{RELEASE}/{name}"), text);
            self
        }

        pub fn db_changed(&self, at: SystemTime) {
            let f = std::fs::File::options()
                .write(true)
                .open(self.path("var/lib/dpkg/status"))
                .unwrap();
            f.set_modified(at).unwrap();
        }

        pub fn booted(&self, at: SystemTime) {
            let s = at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            self.write(
                "proc/stat",
                &format!("cpu  1 2 3\nbtime {s}\nprocesses 9\n"),
            );
        }
    }

    /// A root exec of `exe` as the caller ran it (`filename`), with `argv`.
    pub fn exec(filename: &str, exe: &str, argv: &[&str]) -> Event {
        let comm = filename.rsplit('/').next().unwrap();
        let mut e = crate::decision::rules::testutil::spawn_exe(comm, filename, exe, 0);
        if let Event::ProcessSpawn {
            uid,
            gid,
            argv: a,
            pid,
            timestamp_ns,
            ..
        } = &mut e
        {
            (*uid, *gid) = (0, 0);
            *a = argv.iter().map(|s| s.to_string()).collect();
            // each exec its own key
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (*pid, *timestamp_ns) = (4000 + n as u32, 1_000 + n);
        }
        e
    }

    /// `modprobe <args…>` as xtables and the container runtimes run it.
    pub fn modprobe(args: &[&str]) -> Event {
        let mut argv = vec!["/sbin/modprobe"];
        argv.extend_from_slice(args);
        exec("/sbin/modprobe", "/usr/bin/kmod", &argv)
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{exec, modprobe, HostTree, RELEASE};
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type ModuleRequests = super::ModuleRequests<H>;

    const NF: &str = "kernel/net/netfilter/nf_tables.ko";
    const NFNL: &str = "kernel/net/netfilter/nfnetlink.ko";
    const CRC: &str = "kernel/lib/libcrc32c.ko";

    /// The netfilter modules of a distribution kernel, packaged.
    fn netfilter_host() -> HostTree {
        let t = HostTree::new();
        t.module(CRC, &[], true)
            .module(NFNL, &[], true)
            .module(NF, &[NFNL, CRC], true)
            .packaged("linux-modules-6.8.0-1-generic", &[NF, NFNL, CRC]);
        t
    }

    fn assess(t: &HostTree, e: &Event) -> Assessment {
        ModuleRequests::new(t.root()).of(e)
    }

    fn not_vouched(a: &Assessment) -> &str {
        match a {
            Assessment::NotVouched(why) => why,
            other => panic!("vouched for: {other:?}"),
        }
    }

    #[test]
    fn a_packaged_module_and_its_dependencies_are_vouched_for() {
        let t = netfilter_host();
        let a = assess(&t, &modprobe(&["nf_tables", "-q"]));
        let Assessment::Vouched(what) = &a else {
            panic!("{a:?}")
        };
        assert!(what.contains(NF), "{what}");
        assert!(what.contains("2 dependencies"), "{what}");
        assert!(what.contains("installed by a package"), "{what}");
        // the name as kmod normalises it
        assert!(assess(&t, &modprobe(&["nf-tables"])).records());
        // a merged-/usr exec path and the dpkg list's /lib alias
        assert!(assess(
            &t,
            &exec(
                "/usr/sbin/modprobe",
                "/usr/bin/kmod",
                &["modprobe", "nf_tables"]
            )
        )
        .records());
    }

    #[test]
    fn a_dependency_no_package_installed_is_not_vouched_for() {
        let t = netfilter_host();
        // the dependency is replaced by a hand-copied file under another name
        let rk = "kernel/net/netfilter/nf_helper.ko";
        t.module(rk, &[], true)
            .module("kernel/net/x.ko", &[rk], true);
        t.packaged(
            "linux-modules-6.8.0-1-generic",
            &[NF, NFNL, CRC, "kernel/net/x.ko"],
        );
        let why = assess(&t, &modprobe(&["x"])).clone();
        assert!(
            not_vouched(&why).contains("no package installed it"),
            "{why:?}"
        );
        assert!(not_vouched(&why).contains(rk), "{why:?}");
    }

    /// The decision for "a module copied into /lib/modules then modprobed":
    /// resolved after depmod, but no package lists it — not vouched for;
    /// without depmod nothing resolves it — not vouched for.
    #[test]
    fn a_module_copied_into_the_tree_then_modprobed_is_not_vouched_for() {
        let t = netfilter_host();
        let a = assess(&t, &modprobe(&["rk"]));
        assert!(
            not_vouched(&a).contains("no module of the running kernel's tree"),
            "{a:?}"
        );
        t.module("kernel/drivers/misc/rk.ko", &[], true);
        let a = assess(&t, &modprobe(&["rk"]));
        assert!(not_vouched(&a).contains("no package installed it"), "{a:?}");
    }

    #[test]
    fn a_packaged_file_changed_after_the_package_database_is_not_vouched_for() {
        let t = netfilter_host();
        assert!(assess(&t, &modprobe(&["nf_tables"])).records());
        // the database's last change before the files' (an overwrite after
        // the last transaction)
        t.db_changed(SystemTime::now() - Duration::from_secs(3600));
        let a = assess(&t, &modprobe(&["nf_tables"]));
        assert!(
            not_vouched(&a).contains("after the package database's last change"),
            "{a:?}"
        );
        // (the mtime set back changes nothing, the ctime being the inode's:
        // the Linux host's, nn-linux's `decision_host_linux` tests)
    }

    #[test]
    fn under_signature_enforcement_an_unsigned_image_is_not_vouched_for() {
        let t = netfilter_host();
        t.module("kernel/drivers/net/dummy.ko", &[], false)
            .module("kernel/drivers/net/veth.ko.zst", &[], false)
            .packaged(
                "linux-modules-6.8.0-1-generic",
                &[
                    NF,
                    NFNL,
                    CRC,
                    "kernel/drivers/net/dummy.ko",
                    "kernel/drivers/net/veth.ko.zst",
                ],
            );
        assert!(assess(&t, &modprobe(&["dummy"])).records(), "not enforced");
        t.write("sys/module/module/parameters/sig_enforce", "Y\n");
        let a = assess(&t, &modprobe(&["dummy"]));
        assert!(not_vouched(&a).contains("no appended signature"), "{a:?}");
        assert!(assess(&t, &modprobe(&["nf_tables"])).records(), "signed");
        // a compressed image's signature is inside its stream: the kernel's
        assert!(assess(&t, &modprobe(&["veth"])).records());
        // lockdown enforces it whatever sig_enforce says
        t.write("sys/module/module/parameters/sig_enforce", "N\n");
        t.write(
            "sys/kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        );
        assert!(!assess(&t, &modprobe(&["dummy"])).records());
        t.write(
            "sys/kernel/security/lockdown",
            "[none] integrity confidentiality\n",
        );
        assert!(assess(&t, &modprobe(&["dummy"])).records());
    }

    #[test]
    fn aliases_resolve_as_kmod_resolves_them() {
        let t = netfilter_host();
        t.module("kernel/fs/overlayfs/overlay.ko", &[], true)
            .module("kernel/net/x.ko", &[], true)
            .packaged(
                "linux-modules-6.8.0-1-generic",
                &[NF, NFNL, CRC, "kernel/fs/overlayfs/overlay.ko"],
            )
            .index(
                "modules.alias",
                "alias fs-overlay overlay\nalias pci:v00008086d*sv* x\n",
            )
            .index(
                "modules.symbols",
                "alias symbol:nft_register_obj nf_tables\n",
            )
            .index("modules.builtin", "kernel/fs/ext4/ext4.ko\n")
            .index(
                "modules.builtin.modinfo",
                "ext4.license=GPL\0ext4.alias=fs-ext4\0",
            );
        assert!(assess(&t, &modprobe(&["fs-overlay"])).records());
        assert!(assess(&t, &modprobe(&["symbol:nft_register_obj"])).records());
        let a = assess(&t, &modprobe(&["ext4"]));
        assert!(
            matches!(&a, Assessment::LoadsNothing(w) if w.contains("built in")),
            "{a:?}"
        );
        assert!(matches!(
            assess(&t, &modprobe(&["fs-ext4"])),
            Assessment::LoadsNothing(_)
        ));
        // a built-in beside a file: the file is judged
        let a = assess(&t, &modprobe(&["-a", "ext4", "fs-overlay"]));
        assert!(
            matches!(&a, Assessment::Vouched(w) if w.contains("built in") && w.contains("overlay.ko")),
            "{a:?}"
        );
        // a pattern of modules.alias resolving to an unowned module
        let a = assess(&t, &modprobe(&["pci:v00008086d00001234sv0000"]));
        assert!(not_vouched(&a).contains("no package installed it"), "{a:?}");
        // the configuration's alias comes first: it may point a known name
        // at a module of its own
        t.write("etc/modprobe.d/zz.conf", "# a comment\nalias nf_tables x\n");
        let a = assess(&t, &modprobe(&["nf_tables"]));
        assert!(not_vouched(&a).contains("no package installed it"), "{a:?}");
        // a file of an earlier directory hides one of the same name
        t.write("lib/modprobe.d/zz.conf", "alias nf_tables nf_tables\n");
        assert!(!assess(&t, &modprobe(&["nf_tables"])).records());
        t.write("etc/modprobe.d/zz.conf", "options nf_tables x=1\n");
        assert!(assess(&t, &modprobe(&["nf_tables"])).records());
        // the hidden file's alias is not read
        t.write("lib/modprobe.d/zz.conf", "alias nf_tables x\n");
        assert!(assess(&t, &modprobe(&["nf_tables"])).records());
        std::fs::remove_file(t.path("lib/modprobe.d/zz.conf")).unwrap();
        // an alias naming a module the tree does not hold
        t.write("run/modprobe.d/a.conf", "alias nf-x \\\n  missing_mod\n");
        let a = assess(&t, &modprobe(&["nf-x"]));
        assert!(not_vouched(&a).contains("does not hold"), "{a:?}");
        // the continued line names the module on its next line
        t.write("run/modprobe.d/a.conf", "alias nf-y \\\n  nf_tables\n");
        assert!(assess(&t, &modprobe(&["nf-y"])).records());
    }

    /// The coordinator's case (24.04's lab, k3s): on a kernel whose
    /// nf_tables is built in, `modprobe nft-expr-counter` names a built-in
    /// module by an alias of `modules.builtin.modinfo` — kmod succeeds and
    /// inserts nothing: recorded as a query. A name neither the tree nor the
    /// built-ins resolve stays unresolved: not vouched for (fail-closed).
    #[test]
    fn an_alias_of_a_built_in_module_inserts_nothing() {
        let t = HostTree::new();
        t.module("kernel/net/netfilter/nft_compat.ko.zst", &[], true)
            .packaged("linux-modules-6.8.0-1-generic", &["kernel/net/netfilter/nft_compat.ko.zst"])
            .index("modules.builtin", "kernel/net/netfilter/nf_tables.ko\nkernel/net/netfilter/nfnetlink.ko\n")
            .index(
                "modules.builtin.modinfo",
                "nfnetlink.license=GPL\0nf_tables.license=GPL\0nf_tables.alias=nfnetlink-subsys-10\0\
                 nf_tables.alias=nft-expr-counter\0nf_tables.alias=nft-chain-2-*\0",
            );
        for name in [
            "nft-expr-counter",
            "nft_expr_counter",
            "nfnetlink-subsys-10",
            "nft-chain-2-nat",
        ] {
            let a = assess(&t, &modprobe(&[name]));
            assert!(
                matches!(&a, Assessment::LoadsNothing(w) if w.contains("nf_tables")),
                "{name}: {a:?}"
            );
        }
        // the alias keys only: another key's value is no alias
        for other in ["GPL", "license=GPL"] {
            let a = assess(&t, &modprobe(&[other]));
            assert!(
                not_vouched(&a).contains("no module of the running kernel's tree"),
                "{other}: {a:?}"
            );
        }
        let a = assess(&t, &modprobe(&["nft-expr-nothing"]));
        assert!(
            not_vouched(&a).contains("no module of the running kernel's tree"),
            "{a:?}"
        );
        // a built-in by alias beside a module file: the file judged
        assert!(matches!(
            assess(&t, &modprobe(&["-a", "nft-expr-counter", "nft_compat"])),
            Assessment::Vouched(_)
        ));
    }

    #[test]
    fn soft_dependencies_are_judged_and_a_missing_one_skipped() {
        let t = netfilter_host();
        t.module("kernel/net/x.ko", &[], true);
        t.write(
            "etc/modprobe.d/s.conf",
            "softdep nf_tables pre: nothing_here post: nfnetlink\n",
        );
        assert!(assess(&t, &modprobe(&["nf_tables"])).records());
        t.write("etc/modprobe.d/s.conf", "softdep nf_tables pre: x\n");
        let a = assess(&t, &modprobe(&["nf_tables"]));
        assert!(not_vouched(&a).contains("kernel/net/x.ko"), "{a:?}");
        t.write("etc/modprobe.d/s.conf", "");
        t.index("modules.softdep", "softdep nf_tables post: x\n");
        assert!(!assess(&t, &modprobe(&["nf_tables"])).records());
    }

    #[test]
    fn every_name_of_an_all_must_be_vouched_for() {
        let t = netfilter_host();
        assert!(assess(&t, &modprobe(&["-va", "nf_tables", "nfnetlink"])).records());
        let a = assess(&t, &modprobe(&["-va", "nf_tables", "rk"]));
        assert!(not_vouched(&a).contains("modprobe rk"), "{a:?}");
        // without -a the second operand is a parameter
        assert!(assess(&t, &modprobe(&["nf_tables", "rk"])).records());
    }

    #[test]
    fn a_file_outside_the_tree_or_a_link_is_not_vouched_for() {
        let t = netfilter_host();
        // depmod's external directories name absolute paths
        t.write("opt/mods/ext.ko", "x");
        t.index("modules.dep", "/opt/mods/ext.ko:\n");
        let a = assess(&t, &modprobe(&["ext"]));
        assert!(
            not_vouched(&a).contains("outside the running kernel's tree"),
            "{a:?}"
        );
        t.index("modules.dep", "kernel/../../../../tmp/up.ko:\n");
        assert!(not_vouched(&assess(&t, &modprobe(&["up"]))).contains("leaves the module tree"));
        // (a link in the tree, or behind a linked directory: the Linux
        // host's, nn-linux's `decision_host_linux` tests)
    }

    /// The kernel named a program of a filesystem the host's mount table
    /// does not show (a namespace's own root): not vouched for.
    #[test]
    fn a_program_of_another_namespace_s_filesystem_is_not_vouched_for() {
        let t = netfilter_host();
        let mut e = modprobe(&["nf_tables"]);
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.root = (0x801, 2);
        }
        let a = assess(&t, &e);
        assert!(
            not_vouched(&a).contains("mount table does not show"),
            "{a:?}"
        );
    }

    #[test]
    fn a_host_without_a_package_database_vouches_by_the_kernel_s_own_tree() {
        let t = HostTree::new();
        std::fs::remove_dir_all(t.path("var/lib/dpkg")).unwrap();
        t.module("kernel/net/netfilter/nf_tables.ko.zst", &[], false)
            .module("extra/rk.ko", &[], false)
            .index("modules.order", "kernel/net/netfilter/nf_tables.ko\n");
        // booted after the files were written: unchanged since the boot
        t.booted(SystemTime::now() + Duration::from_secs(60));
        let a = assess(&t, &modprobe(&["nf_tables"]));
        assert!(
            matches!(&a, Assessment::Vouched(w) if w.contains("modules.order")),
            "{a:?}"
        );
        let a = assess(&t, &modprobe(&["rk"]));
        assert!(not_vouched(&a).contains("does not list it"), "{a:?}");
        // the file changed after the boot
        t.booted(SystemTime::now() - Duration::from_secs(60));
        let a = assess(&t, &modprobe(&["nf_tables"]));
        assert!(not_vouched(&a).contains("after the boot"), "{a:?}");
        // no boot time to compare with: not vouched for
        t.write("proc/stat", "cpu 1\n");
        assert!(!assess(&t, &modprobe(&["nf_tables"])).records());
    }

    #[test]
    fn a_dkms_module_is_vouched_for_until_after_its_registry_s_last_change() {
        let t = netfilter_host();
        let rel = "updates/dkms/zfs.ko";
        t.module(rel, &[], true);
        let a = assess(&t, &modprobe(&["zfs"]));
        assert!(
            not_vouched(&a).contains("no package installed it"),
            "not registered: {a:?}"
        );
        std::fs::create_dir_all(t.path(&format!("var/lib/dkms/zfs/2.2.2/{RELEASE}/x86_64/module")))
            .unwrap();
        // built at boot (no package transaction since): its registry is newer
        t.db_changed(SystemTime::now() - Duration::from_secs(3600));
        let a = ModuleRequests::new(t.root()).refresh(&modprobe(&["zfs"]));
        assert!(
            matches!(&a, Some(Assessment::Vouched(w)) if w.contains("built by DKMS")),
            "{a:?}"
        );
    }

    #[test]
    fn what_the_kernel_did_not_say_is_not_vouched_for() {
        let t = netfilter_host();
        let no_argv = exec("/sbin/modprobe", "/usr/bin/kmod", &[]);
        let why = assess(&t, &no_argv);
        assert!(
            not_vouched(&why).contains("no argument was checked"),
            "{why:?}"
        );
        let mut e = modprobe(&["nf_tables"]);
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut e {
            *argv_truncated = true;
        }
        assert!(not_vouched(&assess(&t, &e)).contains("cut at 511 bytes"));
        // the running kernel's release unreadable, its tree absent
        let none = HostTree::new();
        std::fs::remove_file(none.path("proc/sys/kernel/osrelease")).unwrap();
        assert!(not_vouched(&assess(&none, &modprobe(&["nf_tables"]))).contains("release"));
        let empty = HostTree::new();
        std::fs::remove_file(empty.path(&format!("lib/modules/{RELEASE}/modules.dep"))).unwrap();
        assert!(not_vouched(&assess(&empty, &modprobe(&["nf_tables"]))).contains("modules.dep"));
    }

    #[test]
    fn a_query_loads_nothing_and_a_copy_of_the_tool_is_not_vouched_for() {
        let t = HostTree::new();
        for e in [
            modprobe(&["-r", "dummy"]),
            exec("/usr/bin/kmod", "/usr/bin/kmod", &["kmod", "static-nodes"]),
            exec("/usr/sbin/lsmod", "/usr/bin/kmod", &["lsmod"]),
        ] {
            assert!(
                matches!(assess(&t, &e), Assessment::LoadsNothing(_)),
                "{e:?}"
            );
        }
        for e in [
            exec("/tmp/modprobe", "/tmp/modprobe", &["modprobe", "nf_tables"]),
            exec(
                "/usr/sbin/insmod",
                "/usr/bin/kmod",
                &["insmod", "/tmp/rk.ko"],
            ),
            modprobe(&["-d", "/tmp/root", "nf_tables"]),
        ] {
            assert!(!assess(&t, &e).records(), "{e:?}");
        }
    }

    /// Bounded: an index larger than 32 MiB is not read, and one exec is
    /// judged on 64 modules at most — past either, not vouched for.
    #[test]
    fn an_oversized_index_or_too_many_modules_is_not_vouched_for() {
        let t = netfilter_host();
        // a chain of 70 soft dependencies, each a packaged module
        let mut rels = vec![NF, NFNL, CRC];
        let names: Vec<String> = (0..70).map(|i| format!("kernel/s/s{i}.ko")).collect();
        for (i, rel) in names.iter().enumerate() {
            t.module(rel, &[], true);
            if i + 1 < names.len() {
                t.append(
                    "etc/modprobe.d/chain.conf",
                    &format!("softdep s{i} post: s{}\n", i + 1),
                );
            }
        }
        rels.extend(names.iter().map(String::as_str));
        t.packaged("linux-modules-6.8.0-1-generic", &rels);
        let a = assess(&t, &modprobe(&["s60"]));
        assert!(a.records(), "10 modules: {a:?}");
        let a = assess(&t, &modprobe(&["s0"]));
        assert!(not_vouched(&a).contains("more than 64 modules"), "{a:?}");
        // modules.dep past the bound (sparse: no 32 MiB written)
        let dep = std::fs::File::options()
            .write(true)
            .open(t.path(&format!("lib/modules/{RELEASE}/modules.dep")))
            .unwrap();
        dep.set_len(MAX_INDEX_BYTES + 1).unwrap();
        let a = assess(&t, &modprobe(&["nf_tables"]));
        assert!(not_vouched(&a).contains("modules.dep"), "{a:?}");
    }

    /// The exec pump asks dpkg's lists afresh: an answer the module-load
    /// pump kept before a package listed the file is not the pump's.
    #[test]
    fn the_exec_pump_asks_dpkg_afresh_not_the_answer_kept() {
        let t = netfilter_host();
        let late = "kernel/net/late.ko";
        t.module(late, &[], true);
        let owners = super::super::module_provenance::ModuleOwners::<H>::new(t.root());
        let file = format!("/lib/modules/{RELEASE}/{late}");
        assert_eq!(owners.refresh(&file), Provenance::Unowned);
        t.packaged("linux-modules-6.8.0-1-generic", &[NF, NFNL, CRC, late]);
        let a = ModuleRequests::new(t.root()).refresh(&modprobe(&["late"]));
        assert!(a.as_ref().is_some_and(Assessment::records), "{a:?}");
    }

    /// R12b's shape, lot 279: the answer the exec pump made is the one R011
    /// reads — the tree may change between the two.
    #[test]
    fn the_rule_reads_the_answer_the_pump_made() {
        let t = netfilter_host();
        let e = modprobe(&["nf_tables"]);
        let pump = ModuleRequests::new(t.root());
        assert!(pump.refresh(&e).is_some_and(|a| a.records()));
        // the database changes after the pump read the exec
        t.db_changed(SystemTime::now() - Duration::from_secs(3600));
        assert!(
            ModuleRequests::new(t.root()).of(&e).records(),
            "the pump's answer"
        );
        // another exec is assessed afresh
        assert!(!ModuleRequests::new(t.root())
            .of(&modprobe(&["nf_tables"]))
            .records());
        // another comm is none of the pump's
        assert_eq!(
            pump.refresh(&exec("/usr/bin/ls", "/usr/bin/ls", &["ls"])),
            None
        );
    }

    #[test]
    fn fnmatch_and_normalize_as_libc_and_libkmod() {
        let m = |p: &str, s: &str| fnmatch(p.as_bytes(), s.as_bytes());
        assert!(m("pci:v00008086d*sv*", "pci:v00008086d00001234sv0000"));
        assert!(!m("pci:v00008086d*sv*", "pci:v00008087d00001234sv0000"));
        assert!(m("a?c", "abc") && !m("a?c", "ac"));
        assert!(m("x[0-9]y", "x5y") && !m("x[0-9]y", "xay"));
        assert!(m("x[!0-9]y", "xay") && !m("x[^0-9]y", "x5y"));
        assert!(m("x[]]y", "x]y"));
        assert!(m("a[b", "a[b"), "an unclosed class is a plain [");
        assert!(m("a\\*", "a*") && !m("a\\*", "ab"));
        assert!(m("*", "") && m("a*b*c", "axxbyyc") && !m("a*b*c", "axxbyy"));
        // a star gives back one character at a time
        assert!(m("*ab", "aab") && m("*:v*d*", "pci:v1d2"));
        assert_eq!(normalize("nf-tables").as_deref(), Some("nf_tables"));
        assert_eq!(normalize("usb:v[0-9]-x").as_deref(), Some("usb:v[0-9]_x"));
        assert_eq!(normalize("a]b"), None);
        assert_eq!(normalize("a[b"), None);
        assert_eq!(normalize(""), None);
        assert_eq!(
            modname("kernel/drivers/net/nvidia-uvm.ko.zst"),
            "nvidia_uvm"
        );
    }
}
