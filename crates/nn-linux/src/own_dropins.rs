//! Lot 273d (the review of #492): the drop-ins of our own units'
//! directories made inside a trusted-installer window, judged at its close.
//!
//! Outside a window those directories refuse a new entry (NOCREATE);
//! inside one an operator's tooling may leave one — a `set-property` writes
//! `50-<Property>.conf` under `system.control` — and it stays after the
//! window. systemd applies it at its next reload (the agent asks for one,
//! an attacker can provoke one) and at the unit's next start. At the
//! window's close each such drop-in, made or changed since the window
//! opened, is judged as the host's are (`crate::host_dropins`) against its
//! own unit's floors and semantics: a harmful one is moved to the
//! quarantine — these are our units' own files, not the host's — the move
//! is in the window's signed close record, and systemd reloads (at most
//! one a [`crate::systemd_reload::MIN_INTERVAL`]). The drop-ins
//! `install.sh` lays down are known by their content and left.
//!
//! The re-review of #497: a drop-in kept, and the environment file under
//! [`ENV_FILE_DIR`] it names, are write-protected ([`Protector`], RR1);
//! the integrity round judges again only what changed since the agent's
//! install ([`install_time`]) — one the operator had before is listed by
//! `install.sh --upgrade` (the agent's `--own-dropins check`), never moved
//! by the round (RR2).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::host_dropins::{breaks, directives, effective, harms, HostLimits, Kind, Reach};

/// Where a quarantined drop-in goes.
pub const QUARANTINE_DIR: &str = "/var/lib/northnarrow/quarantine/dropins";

/// Our units' drop-in directories under `root`, and whom each reaches.
pub fn own_dirs(root: &Path) -> [(PathBuf, Reach); 4] {
    [
        (root.join("northnarrow-agent.service.d"), Reach::Agent),
        (root.join("northnarrow-watchdog.service.d"), Reach::Watchdog),
        (root.join("northnarrow-.service.d"), Reach::Services),
        // lot 273d: the units' slice of their own
        (root.join("northnarrow.slice.d"), Reach::OurSlice),
    ]
}

/// One drop-in moved, or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub from: PathBuf,
    pub to: Option<PathBuf>,
    pub why: String,
    pub error: Option<String>,
}

impl Moved {
    pub fn detail(&self) -> String {
        match (&self.to, &self.error) {
            (Some(to), None) => format!(
                "{}: {}; moved to {}",
                self.from.display(),
                self.why,
                to.display()
            ),
            (_, e) => format!(
                "{}: {}; NOT moved ({})",
                self.from.display(),
                self.why,
                e.as_deref().unwrap_or("?")
            ),
        }
    }
}

/// The directory an `EnvironmentFile=` of our units may name: our own
/// configuration, protected (the review of #497, D4 — a file anywhere else
/// can change after the judgment, outside any window).
pub const ENV_FILE_DIR: &str = "/etc/northnarrow/";

/// The judged directory's entry: changed at or after `since`, by its
/// ctime — which no `touch -d` sets back and a new hard link, a rename or
/// a content change all move (the review of #497, D4: the mtime did not
/// hold). An unreadable ctime counts as changed.
fn changed_since(meta: &std::fs::Metadata, since: SystemTime) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(s) = since.duration_since(SystemTime::UNIX_EPOCH) else {
        return true;
    };
    let ct = std::time::Duration::new(
        meta.ctime().max(0) as u64,
        meta.ctime_nsec().clamp(0, 999_999_999) as u32,
    );
    ct >= s
}

/// When the running agent was installed: its binary's ctime (`install.sh`
/// stages it and renames it in, a package unpacks it; outside a window no
/// one changes it — it is a protected file). The integrity round judges
/// only our drop-ins changed since (the re-review of #497, RR2). `None`
/// when it cannot be read: the round then judges none.
pub fn install_time() -> Option<SystemTime> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata("/proc/self/exe").ok()?;
    let secs = u64::try_from(meta.ctime()).ok()?;
    Some(
        SystemTime::UNIX_EPOCH
            + std::time::Duration::new(secs, meta.ctime_nsec().clamp(0, 999_999_999) as u32),
    )
}

/// The `EnvironmentFile=`s of a drop-in's text, the `-` (optional) taken
/// off.
fn env_files(text: &str) -> Vec<String> {
    effective(directives(text))
        .into_iter()
        .filter(|(k, _)| k == "EnvironmentFile")
        .flat_map(|(_, v)| {
            v.split_whitespace()
                .map(|f| f.trim_start_matches('-').to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `f` names a file under [`ENV_FILE_DIR`]: absolute, inside it, with no
/// `.` or `..` that could lead out of it.
fn under_env_dir(f: &str) -> bool {
    use std::path::Component;
    let p = Path::new(f);
    f.starts_with(ENV_FILE_DIR)
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// The loader's variables: harmful in our units' environment whatever the
/// window (the coordinator's decision on #497's `NN_` drop-ins).
pub const LOADER_ENV: &[&str] = crate::host_dropins::DANGEROUS_ENV_NAMES;

/// The `NN_` switches that weaken the agent when a drop-in of ours sets
/// them — besides [`crate::self_integrity::WEAKENING_ENV`] (the agent's own
/// start judges those too): a sensor back to its older fallback, the exec
/// policy off. Each one kept is a High alert, not an informative record.
pub const WEAKENING_DROPIN_EXTRA: &[(&str, crate::self_integrity::WeakensWith)] = &[
    ("NN_FILE_OPEN_SENSOR", |v| v.trim() == "tracepoint"),
    ("NN_EXEC_SENSOR", |v| v.trim() == "tracepoint"),
    ("NN_DNS_SENSOR", |v| v.trim() == "sendmsg"),
    ("NN_EXEC_POLICY", |v| v.trim() == "off"),
];

/// `name=value` weakens the agent ([`WEAKENING_DROPIN_EXTRA`],
/// [`crate::self_integrity::WEAKENING_ENV`]).
pub fn nn_weakens(name: &str, value: &str) -> bool {
    crate::self_integrity::WEAKENING_ENV
        .iter()
        .chain(WEAKENING_DROPIN_EXTRA)
        .any(|(n, weakens)| *n == name && weakens(value))
}

/// `name=value` assignments of an `Environment=` value (quotes taken off).
fn env_assignments(v: &str) -> Vec<(String, String)> {
    v.split_whitespace()
        .filter_map(|a| {
            let a = a.trim_matches('"');
            a.split_once('=')
                .map(|(n, val)| (n.to_string(), val.to_string()))
        })
        .collect()
}

/// `name=value` lines of an environment file (`export` and blanks taken
/// off, comments skipped).
fn env_file_assignments(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim().trim_start_matches("export ").trim();
            if l.starts_with('#') {
                return None;
            }
            l.split_once('=')
                .map(|(n, v)| (n.trim().to_string(), v.trim().trim_matches('"').to_string()))
        })
        .collect()
}

/// The judge of one directive of OUR units' drop-ins: the host's
/// ([`harms`]), except for the environment (the coordinator's decision on
/// #497's `NN_` drop-ins): a loader variable ([`LOADER_ENV`]) is harmful,
/// an `NN_` one is the operator's configuration — kept, each one signed
/// ([`nn_settings`]). An `EnvironmentFile=` is read the same way (it lies
/// under [`ENV_FILE_DIR`] by then: [`shape_harm`]).
fn own_harms(reach: Reach, key: &str, value: &str, host: &HostLimits) -> Option<String> {
    match key {
        "Environment" => env_assignments(value)
            .into_iter()
            .find(|(n, _)| LOADER_ENV.contains(&n.as_str()))
            .map(|(n, _)| format!("{n} set in our units' environment")),
        "EnvironmentFile" => {
            let p = value.trim().trim_start_matches('-');
            let text = std::fs::read_to_string(p).unwrap_or_default();
            env_file_assignments(&text)
                .into_iter()
                .find(|(n, _)| LOADER_ENV.contains(&n.as_str()))
                .map(|(n, _)| format!("{n} set in our units' environment (from {p})"))
        }
        _ => harms(reach, key, value, host),
    }
}

/// An `NN_` setting a kept drop-in of ours gives our units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NnSetting {
    pub dropin: PathBuf,
    pub name: String,
    pub value: String,
    /// One of the switches that weaken the agent ([`nn_weakens`]).
    pub weakens: bool,
}

impl NnSetting {
    pub fn detail(&self) -> String {
        format!(
            "{}={} set by {}{}",
            self.name,
            self.value,
            self.dropin.display(),
            if self.weakens {
                " — a switch that weakens the agent"
            } else {
                ""
            }
        )
    }
}

/// The coordinator's decision on #497's `NN_` drop-ins: every `NN_`
/// setting the regular single-name drop-ins of our directories give our
/// units — `Environment=` and the `EnvironmentFile=`s under
/// [`ENV_FILE_DIR`] — for a signed record each (a High alert for one that
/// weakens the agent).
pub fn nn_settings(roots: &[&Path]) -> Vec<NnSetting> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        for (dir, _) in own_dirs(root) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            if let Ok(canon) = std::fs::canonicalize(&dir) {
                if !seen.insert(canon) {
                    continue;
                }
            }
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for from in files {
                if from.extension().and_then(|x| x.to_str()) != Some("conf")
                    || !regular_with_one_name(&from)
                {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&from) else {
                    continue;
                };
                for (k, v) in effective(directives(&text)) {
                    let pairs = match k.as_str() {
                        "Environment" => env_assignments(&v),
                        "EnvironmentFile" => {
                            let p = v.trim().trim_start_matches('-');
                            if !under_env_dir(p) {
                                continue;
                            }
                            env_file_assignments(&std::fs::read_to_string(p).unwrap_or_default())
                        }
                        _ => continue,
                    };
                    for (name, value) in pairs {
                        if name.starts_with("NN_") {
                            out.push(NnSetting {
                                dropin: from.clone(),
                                weakens: nn_weakens(&name, &value),
                                name,
                                value,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

/// `path` is a regular file with one name (`lstat`: a symlink is not).
pub fn regular_with_one_name(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file() && m.nlink() == 1)
}

/// Why an entry of our directories is quarantined whatever its directives
/// say (the review of #497, D4): not a regular file (a symlink systemd
/// follows to a target outside our directories), a hard link (its content
/// changes through another name), an `EnvironmentFile=` outside
/// [`ENV_FILE_DIR`] — or, the re-review of #497 (RR1), one inside it that
/// `protect` cannot keep from changing without a window (not a regular
/// file with one name, or its write protection not registered).
fn shape_harm(
    meta: &std::fs::Metadata,
    from: &Path,
    text: Option<&str>,
    protect: &mut dyn FnMut(&Path) -> bool,
) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    if meta.file_type().is_symlink() {
        let to = std::fs::read_link(from)
            .map(|t| t.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        return Some(format!(
            "a symlink to {to}: its target lies outside our directories and changes without a window"
        ));
    }
    if !meta.file_type().is_file() {
        return Some("not a regular file".to_string());
    }
    if meta.nlink() > 1 {
        return Some(format!(
            "a hard link ({} names): its content changes through a name outside our directories",
            meta.nlink()
        ));
    }
    for f in env_files(text?) {
        if !under_env_dir(&f) {
            return Some(format!(
                "EnvironmentFile={f} lies outside {ENV_FILE_DIR}: its content changes after the judgment"
            ));
        }
        if !protect(Path::new(&f)) {
            return Some(format!(
                "EnvironmentFile={f} is not a protected regular file with one name: its content changes without a window"
            ));
        }
    }
    None
}

/// How a pass over our units' drop-in directories judges.
#[derive(Debug, Clone, Copy)]
pub struct Pass<'a> {
    /// An entry changed (its ctime) at or after it is judged; one changed
    /// before is only kept protected.
    pub since: SystemTime,
    /// How a record names the entries this pass judges.
    pub when: &'a str,
}

/// [`Pass::when`] at a window's close (since its opening).
pub const AT_CLOSE: &str = "made inside the window";
/// [`Pass::when`] at the integrity round (since the agent's install, the
/// re-review of #497, RR2: a drop-in the operator had before is never
/// moved by the round — `install.sh --upgrade` lists it first).
pub const AT_ROUND: &str = "changed outside a window since the agent was installed";
/// [`Pass::when`] of the installer's check (every entry).
pub const AT_CHECK: &str = "found by the installer's check";
/// [`Pass::when`] of a harmful drop-in from before the install, which the
/// round reports and never moves (the short re-check of #497, RB1).
pub const AT_PREINSTALL: &str = "there before the agent was installed";

/// A harmful entry of our directories, not moved yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Harmful {
    pub from: PathBuf,
    pub why: String,
    /// What the quarantine keeps of it: its bytes, a symlink's target.
    keep: Vec<u8>,
}

/// The harmful drop-ins of our units' directories under `roots`: each
/// entry changed at or after `pass.since` (by its ctime) judged against
/// its own unit's floors and semantics. `known`: a drop-in `install.sh`
/// lays down, left. Whatever its directives, a symlink, a hard link and an
/// `EnvironmentFile=` outside [`ENV_FILE_DIR`] are harmful (the review of
/// #497, D4), and so is one inside it that `protect` does not hold.
///
/// The re-review of #497 (RR1): every entry kept — a regular file with one
/// name, judged harmless or not judged in this pass — and the
/// `EnvironmentFile=`s it names under [`ENV_FILE_DIR`] go through
/// `protect`, which registers their write protection (a [`Protector`]): a
/// kept drop-in no longer changes without a window. Read-only callers
/// pass a `protect` that only looks ([`regular_with_one_name`]).
pub fn harmful(
    roots: &[&Path],
    host: &HostLimits,
    pass: Pass<'_>,
    known: impl Fn(&Path, &[u8]) -> bool,
    protect: &mut dyn FnMut(&Path) -> bool,
) -> Vec<Harmful> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        for (dir, reach) in own_dirs(root) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            if let Ok(canon) = std::fs::canonicalize(&dir) {
                if !seen.insert(canon) {
                    continue;
                }
            }
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for from in files {
                if from.extension().and_then(|x| x.to_str()) != Some("conf") {
                    continue;
                }
                let Ok(meta) = std::fs::symlink_metadata(&from) else {
                    continue;
                };
                let regular = meta.file_type().is_file();
                let bytes = if regular {
                    std::fs::read(&from).ok()
                } else {
                    None
                };
                if regular && bytes.is_none() {
                    continue;
                }
                let text = bytes
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).to_string());
                let single = regular && meta_nlink(&meta) == 1;
                if !changed_since(&meta, pass.since) {
                    if single {
                        keep_protected(&from, text.as_deref(), protect);
                    }
                    continue;
                }
                if let Some(b) = &bytes {
                    if single && known(&from, b) {
                        keep_protected(&from, text.as_deref(), protect);
                        continue;
                    }
                }
                let when = pass.when;
                let why = shape_harm(&meta, &from, text.as_deref(), protect)
                    .map(|w| format!("{when}, {w}"))
                    .or_else(|| {
                        effective(directives(text.as_deref()?))
                            .into_iter()
                            .find_map(|(k, v)| {
                                own_harms(reach, &k, &v, host)
                                    .map(|w| (k.clone(), v.clone(), w, Kind::Harmful))
                                    .or_else(|| {
                                        breaks(&k, &v).map(|w| (k, v, w, Kind::BreaksAgent))
                                    })
                            })
                            .map(|(k, v, w, _)| format!("{when}, sets {k}={v}: {w}"))
                    });
                let Some(why) = why else {
                    keep_protected(&from, text.as_deref(), protect);
                    continue;
                };
                // a symlink is kept as its target's name, never followed
                let keep = bytes.unwrap_or_else(|| {
                    format!(
                        "symlink -> {}\n",
                        std::fs::read_link(&from)
                            .map(|t| t.display().to_string())
                            .unwrap_or_default()
                    )
                    .into_bytes()
                });
                out.push(Harmful { from, why, keep });
            }
        }
    }
    out
}

/// A kept drop-in and the `EnvironmentFile=`s it names under
/// [`ENV_FILE_DIR`], through `protect` (the re-review of #497, RR1).
fn keep_protected(from: &Path, text: Option<&str>, protect: &mut dyn FnMut(&Path) -> bool) {
    protect(from);
    for f in text.map(env_files).unwrap_or_default() {
        if under_env_dir(&f) {
            protect(Path::new(&f));
        }
    }
}

/// The short re-check of #497 (RB1): the harmful drop-ins of our
/// directories older than `installed` (their ctime) — a package install
/// runs no installer's check, and the round never moves them (RR2) — for
/// the round to report, signed, with the remedy. Read-only: nothing moved,
/// nothing registered.
pub fn preinstall_harmful(
    roots: &[&Path],
    host: &HostLimits,
    installed: SystemTime,
    known: impl Fn(&Path, &[u8]) -> bool,
) -> Vec<Harmful> {
    let pass = Pass {
        since: SystemTime::UNIX_EPOCH,
        when: AT_PREINSTALL,
    };
    harmful(roots, host, pass, known, &mut |p| regular_with_one_name(p))
        .into_iter()
        .filter(|h| std::fs::symlink_metadata(&h.from).is_ok_and(|m| !changed_since(&m, installed)))
        .collect()
}

/// [`harmful`]'s entries moved into `quarantine` (`now`: the name's
/// stamp), each one's move or failure.
pub fn quarantine(
    roots: &[&Path],
    host: &HostLimits,
    pass: Pass<'_>,
    quarantine: &Path,
    now: u64,
    known: impl Fn(&Path, &[u8]) -> bool,
    protect: &mut dyn FnMut(&Path) -> bool,
) -> Vec<Moved> {
    harmful(roots, host, pass, known, protect)
        .into_iter()
        .map(|h| move_one(h, quarantine, now))
        .collect()
}

fn move_one(h: Harmful, quarantine: &Path, now: u64) -> Moved {
    let name: String = h
        .from
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
        .and_then(|()| std::fs::write(&to, &h.keep))
        .and_then(|()| std::fs::remove_file(&h.from));
    match moved {
        Ok(()) => Moved {
            from: h.from,
            to: Some(to),
            why: h.why,
            error: None,
        },
        Err(e) => {
            let _ = std::fs::remove_file(&to);
            Moved {
                from: h.from,
                to: None,
                why: h.why,
                error: Some(e.to_string()),
            }
        }
    }
}

fn meta_nlink(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

/// The installer's check (`northnarrow-agent --own-dropins`, the re-review
/// of #497, RR2): our units' drop-ins under `prefix` (`/` on the host)
/// against this build's judge, every one whatever its age. `quarantine`
/// false: each one the agent would quarantine printed as `would move
/// <path>: <why>`, nothing moved — 3 when there is one, 0 when none.
/// `quarantine` true (the operator accepted it): each moved into
/// `quarantine_dir`, `moved <path> -> <to>: <why>` — 1 when one could not
/// be. An environment file under [`ENV_FILE_DIR`] counts as held when it
/// is a regular file with one name: the agent protects it at its next pass.
pub fn installer_check(
    prefix: &Path,
    host: &HostLimits,
    quarantine_dir: &Path,
    quarantine: bool,
    now: u64,
    out: &mut dyn std::io::Write,
) -> i32 {
    let roots = crate::self_integrity::unit_roots(prefix);
    let search: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    let pass = Pass {
        since: SystemTime::UNIX_EPOCH,
        when: AT_CHECK,
    };
    let known = crate::self_integrity::is_known_dropin;
    let mut held = |p: &Path| regular_with_one_name(p);
    if !quarantine {
        let found = harmful(&search, host, pass, known, &mut held);
        for h in &found {
            let _ = writeln!(out, "would move {}: {}", h.from.display(), h.why);
        }
        // the coordinator's decision on #497's `NN_` drop-ins: the agent's
        // settings are kept configuration, listed, never a refusal
        for n in nn_settings(&search) {
            if !found.iter().any(|h| h.from == n.dropin) {
                let _ = writeln!(out, "would keep {}", n.detail());
            }
        }
        return if found.is_empty() { 0 } else { 3 };
    }
    let moved = self::quarantine(&search, host, pass, quarantine_dir, now, known, &mut held);
    let mut failed = false;
    for m in &moved {
        match &m.to {
            Some(to) => {
                let _ = writeln!(
                    out,
                    "moved {} -> {}: {}",
                    m.from.display(),
                    to.display(),
                    m.why
                );
            }
            None => {
                failed = true;
                let _ = writeln!(out, "NOT moved {}", m.detail());
            }
        }
    }
    i32::from(failed)
}

/// The inode keys a [`Protector`] registered itself, by path, across its
/// passes — the window's close and the integrity round share one
/// (`TrustedInstallerOverride::own_dropin_keys`): a key whose path no
/// longer names it is taken out, so a freed inode number never protects
/// another file. Keys registered at boot are not here and never taken out
/// by a pass.
pub type Registered = std::sync::Mutex<std::collections::BTreeMap<PathBuf, (u64, u64)>>;

/// The degradation a [`Protector`] without the protected-inode map signs.
pub const UNPROTECTED: &str = "own_dropins_unprotected";

/// The protected-inode map as a [`Protector`] uses it.
pub trait InodeMap {
    fn flags(&self, key: common::wire::InodeKey) -> Option<u8>;
    fn register(&mut self, key: common::wire::InodeKey, flags: u8) -> anyhow::Result<()>;
    fn remove(&mut self, key: common::wire::InodeKey) -> anyhow::Result<()>;
}

impl InodeMap for crate::anti_tamper::filesystem::ProtectedInodesHandle {
    fn flags(&self, key: common::wire::InodeKey) -> Option<u8> {
        crate::anti_tamper::filesystem::ProtectedInodesHandle::flags(self, key)
    }
    fn register(&mut self, key: common::wire::InodeKey, flags: u8) -> anyhow::Result<()> {
        crate::anti_tamper::filesystem::ProtectedInodesHandle::register(self, key, flags)
    }
    fn remove(&mut self, key: common::wire::InodeKey) -> anyhow::Result<()> {
        crate::anti_tamper::filesystem::ProtectedInodesHandle::remove(self, key)
    }
}

/// The re-review of #497 (RR1): the write protection of the drop-ins a
/// pass keeps and of the `EnvironmentFile=`s they name under
/// [`ENV_FILE_DIR`] — `FS_PROTECT_WRITE | FS_PROTECT_MUTATE` in the pinned
/// protected-inode map, added to what a key already has. Outside a window
/// root can no longer rewrite them (a `50-CPUQuota.conf` kept at a close
/// turned into `ExecStartPre=`, applied at the next boot before the agent
/// runs). A window lifts it as it lifts every protected file's.
pub struct Protector<'a, M: InodeMap = crate::anti_tamper::filesystem::ProtectedInodesHandle> {
    map: Option<M>,
    ours: std::sync::MutexGuard<'a, std::collections::BTreeMap<PathBuf, (u64, u64)>>,
    kept: std::collections::BTreeMap<PathBuf, (u64, u64)>,
}

impl<'a> Protector<'a> {
    /// The pinned map under `bpffs_root`, with the keys `registered`
    /// records. The short re-check of #497 (NB6): without it nothing is
    /// protected — every [`Self::protect`] says so (fail-closed: an
    /// environment file is then not held, its drop-in quarantined). A map
    /// that cannot be opened is a signed degradation ([`UNPROTECTED`])
    /// until it opens again; no root at all is a boot without deny hooks,
    /// a degradation of its own.
    pub fn open(bpffs_root: Option<&Path>, registered: &'a Registered) -> Self {
        // no root: no deny hook this boot, a degradation already signed
        let map = bpffs_root.and_then(|r| {
            match crate::anti_tamper::filesystem::ProtectedInodesHandle::open(r) {
                Ok(m) => {
                    crate::boot::degradation::withdraw(UNPROTECTED, &[]);
                    Some(m)
                }
                Err(e) => {
                    let e = format!("{e:#}");
                    tracing::warn!(error = %e, "our drop-ins: the protected-inode map cannot be opened — not protected");
                    crate::boot::degradation::report(
                        UNPROTECTED,
                        &format!(
                            "our units' kept drop-ins and their environment files are not \
                             write-protected: {e}"
                        ),
                    );
                    None
                }
            }
        });
        Self::with_map(map, registered)
    }
}

impl<'a, M: InodeMap> Protector<'a, M> {
    /// Over `map`, with the keys `registered` records (held for the pass).
    pub fn with_map(map: Option<M>, registered: &'a Registered) -> Self {
        Self {
            map,
            ours: registered.lock().unwrap_or_else(|p| p.into_inner()),
            kept: std::collections::BTreeMap::new(),
        }
    }

    /// `path` is a regular file with one name, now write-protected.
    pub fn protect(&mut self, path: &Path) -> bool {
        use common::wire::{InodeKey, FS_PROTECT_MUTATE, FS_PROTECT_WRITE};
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if !meta.file_type().is_file() || meta.nlink() != 1 {
            return false;
        }
        // the short re-check of #497 (NB6): no map, nothing protected —
        // fail-closed (the degradation is signed by `open`)
        let Some(map) = self.map.as_mut() else {
            return false;
        };
        let key = InodeKey {
            dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        let had = map.flags(key);
        let want = had.unwrap_or(0) | FS_PROTECT_WRITE | FS_PROTECT_MUTATE;
        if had != Some(want) {
            if let Err(e) = map.register(key, want) {
                tracing::warn!(
                    path = %path.display(),
                    error = %format!("{e:#}"),
                    "our drop-ins: write protection not registered"
                );
                return false;
            }
        }
        let k = (key.dev, key.ino);
        if had.is_none() || self.ours.get(path) == Some(&k) {
            self.kept.insert(path.to_path_buf(), k);
        }
        true
    }

    /// The pass is over: a key a pass registered whose path this one did
    /// not keep with it is taken out of the map (handed back).
    pub fn finish(mut self) -> Option<M> {
        let gone: Vec<(PathBuf, (u64, u64))> = self
            .ours
            .iter()
            .filter(|(p, k)| self.kept.get(*p) != Some(*k))
            .map(|(p, k)| (p.clone(), *k))
            .collect();
        for (p, (dev, ino)) in gone {
            if !self.kept.values().any(|k| *k == (dev, ino)) {
                if let Some(map) = self.map.as_mut() {
                    let _ = map.remove(common::wire::InodeKey { dev, ino });
                }
            }
            self.ours.remove(&p);
        }
        let kept = std::mem::take(&mut self.kept);
        self.ours.extend(kept);
        self.map.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(since: SystemTime) -> Pass<'static> {
        Pass {
            since,
            when: AT_CLOSE,
        }
    }

    fn host() -> HostLimits {
        HostLimits {
            mem_total: 16 << 30,
            tasks_max: 4_194_304,
            cpus: vec![0, 1, 2, 3],
            ..Default::default()
        }
    }

    #[test]
    fn a_harmful_drop_in_made_inside_the_window_is_moved_and_the_rest_left() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let ag = root.path().join("northnarrow-agent.service.d");
        let wd = root.path().join("northnarrow-watchdog.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        std::fs::create_dir_all(&wd).unwrap();
        // below the agent's floor: moved
        std::fs::write(ag.join("50-MemoryMax.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        // the watchdog's own 64M is not below ITS floor: left
        std::fs::write(wd.join("50-MemoryMax.conf"), "[Service]\nMemoryMax=64M\n").unwrap();
        // install.sh's: left
        std::fs::write(ag.join("10-known.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        let r = quarantine(
            &[root.path()],
            &host(),
            close(since),
            q.path(),
            1700000000,
            |p, _| p.ends_with("10-known.conf"),
            &mut |_| true,
        );
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0]
            .detail()
            .contains("50-MemoryMax.conf: made inside the window, sets MemoryMax=4K"));
        assert!(!ag.join("50-MemoryMax.conf").exists());
        assert!(wd.join("50-MemoryMax.conf").exists());
        assert!(ag.join("10-known.conf").exists());
        assert_eq!(std::fs::read_dir(q.path()).unwrap().count(), 1);
        // a drop-in changed before the window is not judged here
        std::fs::write(ag.join("60-old.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        let later = SystemTime::now() + std::time::Duration::from_secs(60);
        assert!(quarantine(
            &[root.path()],
            &host(),
            close(later),
            q.path(),
            1,
            |_, _| false,
            &mut |_| true
        )
        .is_empty());
    }

    /// The review of #497 (D4): an mtime set back (`touch -d`) does not
    /// hide a drop-in made inside the window — its ctime selects it.
    #[test]
    fn an_mtime_set_back_does_not_hide_a_drop_in() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let f = ag.join("50-MemoryMax.conf");
        std::fs::write(&f, "[Service]\nMemoryMax=4K\n").unwrap();
        let old = std::fs::FileTimes::new()
            .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000));
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_times(old)
            .unwrap();
        assert!(std::fs::metadata(&f).unwrap().modified().unwrap() < since);
        let r = quarantine(
            &[root.path()],
            &host(),
            close(since),
            q.path(),
            1,
            |_, _| false,
            &mut |_| true,
        );
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(!f.exists());
    }

    /// The review of #497 (D4): a symlink, a hard link and an
    /// `EnvironmentFile=` outside /etc/northnarrow are quarantined whatever
    /// they set; the symlink's target is never written or followed.
    #[test]
    fn a_link_or_an_outside_environment_file_is_quarantined() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let target = outside.path().join("x.conf");
        std::fs::write(&target, "[Service]\nMemoryMax=2G\n").unwrap();
        std::os::unix::fs::symlink(&target, ag.join("50-link.conf")).unwrap();
        let shared = outside.path().join("shared.conf");
        std::fs::write(&shared, "[Service]\nMemoryMax=2G\n").unwrap();
        std::fs::hard_link(&shared, ag.join("51-hard.conf")).unwrap();
        std::fs::write(
            ag.join("52-env.conf"),
            "[Service]\nEnvironmentFile=-/var/tmp/nn.env\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("53-ours.conf"),
            "[Service]\nEnvironmentFile=/etc/northnarrow/agent.env\nMemoryMax=2G\n",
        )
        .unwrap();
        let r = quarantine(
            &[root.path()],
            &host(),
            close(since),
            q.path(),
            7,
            |_, _| false,
            &mut |_| true,
        );
        let why: Vec<String> = r.iter().map(Moved::detail).collect();
        assert_eq!(r.len(), 3, "{why:#?}");
        assert!(
            why[0].contains("50-link.conf: made inside the window, a symlink to"),
            "{why:#?}"
        );
        assert!(
            why[1].contains("51-hard.conf: made inside the window, a hard link (2 names)"),
            "{why:#?}"
        );
        assert!(
            why[2].contains("EnvironmentFile=/var/tmp/nn.env lies outside /etc/northnarrow/"),
            "{why:#?}"
        );
        assert!(r.iter().all(|m| m.to.is_some()), "{why:#?}");
        // the link's target untouched; ours (under /etc/northnarrow) kept
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "[Service]\nMemoryMax=2G\n"
        );
        assert!(shared.exists());
        assert!(ag.join("53-ours.conf").exists());
        let kept: Vec<String> = std::fs::read_dir(q.path())
            .unwrap()
            .flatten()
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        assert!(
            kept.iter().any(|k| k.starts_with("symlink -> ")),
            "{kept:?}"
        );
    }

    /// The re-review of #497 (RR1): a kept drop-in, and the environment
    /// file under /etc/northnarrow it names, go through `protect` — judged
    /// in this pass or not; an environment file `protect` does not hold
    /// (not a regular file with one name, its protection not registered)
    /// quarantines the drop-in; `..` never leads out of /etc/northnarrow.
    #[test]
    fn a_kept_drop_in_and_its_environment_file_are_write_protected() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        // before the pass: not judged, kept protected all the same
        std::fs::write(ag.join("40-old.conf"), "[Service]\nCPUQuota=80%\n").unwrap();
        let since = SystemTime::now() + std::time::Duration::from_secs(60);
        let mut calls: Vec<PathBuf> = Vec::new();
        let r = quarantine(
            &[root.path()],
            &host(),
            close(since),
            q.path(),
            1,
            |_, _| false,
            &mut |p| {
                calls.push(p.to_path_buf());
                true
            },
        );
        assert!(r.is_empty(), "{r:?}");
        assert_eq!(calls, vec![ag.join("40-old.conf")]);
        // inside the pass: a harmless one with its environment file, one
        // whose environment file is not held, one that climbs out with ..
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        std::fs::write(
            ag.join("50-CPUQuota.conf"),
            "[Service]\nCPUQuota=80%\nEnvironmentFile=/etc/northnarrow/agent.env\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("51-extra.conf"),
            "[Service]\nEnvironmentFile=-/etc/northnarrow/extra.env\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("52-climb.conf"),
            "[Service]\nEnvironmentFile=/etc/northnarrow/../../var/tmp/nn.env\n",
        )
        .unwrap();
        let mut calls: Vec<PathBuf> = Vec::new();
        let r = quarantine(
            &[root.path()],
            &host(),
            close(since),
            q.path(),
            2,
            |_, _| false,
            &mut |p| {
                calls.push(p.to_path_buf());
                p != Path::new("/etc/northnarrow/extra.env")
            },
        );
        let why: Vec<String> = r.iter().map(Moved::detail).collect();
        assert_eq!(r.len(), 2, "{why:#?}");
        assert!(
            why[0].contains(
                "51-extra.conf: made inside the window, EnvironmentFile=/etc/northnarrow/extra.env \
                 is not a protected regular file with one name"
            ),
            "{why:#?}"
        );
        assert!(
            why[1].contains("EnvironmentFile=/etc/northnarrow/../../var/tmp/nn.env lies outside"),
            "{why:#?}"
        );
        assert!(ag.join("50-CPUQuota.conf").exists());
        // the kept ones and the environment file the kept one names
        for p in [
            ag.join("40-old.conf"),
            ag.join("50-CPUQuota.conf"),
            PathBuf::from("/etc/northnarrow/agent.env"),
        ] {
            assert!(calls.contains(&p), "{p:?} not protected: {calls:#?}");
        }
        assert!(!calls.contains(&ag.join("51-extra.conf")), "{calls:#?}");
        assert!(!calls.contains(&ag.join("52-climb.conf")), "{calls:#?}");
    }

    /// The re-review of #497 (RR2), with the reviewer's probe: the
    /// installer's check lists the operator's drop-ins the agent would
    /// quarantine — an `EnvironmentFile=` outside /etc/northnarrow, a
    /// `CPUAffinity=` below the online CPUs, an environment file under it
    /// that is not there to protect — and moves nothing; the integrity
    /// round, which judges only what changed since the agent's install,
    /// moves none of them.
    #[test]
    fn the_operator_s_drop_ins_from_before_the_install_are_listed_never_moved_by_the_round() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let cases = [
            (
                "override.conf",
                "[Service]\nEnvironmentFile=-/etc/default/northnarrow-agent\n",
            ),
            ("10-pin.conf", "[Service]\nCPUAffinity=0\n"),
            ("20-log.conf", "[Service]\nEnvironment=RUST_LOG=info\n"),
            (
                "30-ours-env.conf",
                "[Service]\nEnvironmentFile=/etc/northnarrow/nn-test-absent.env\n",
            ),
        ];
        for (n, t) in cases {
            std::fs::write(ag.join(n), t).unwrap();
        }
        let check = Pass {
            since: SystemTime::UNIX_EPOCH,
            when: AT_CHECK,
        };
        let listed = harmful(&[root.path()], &host(), check, |_, _| false, &mut |p| {
            regular_with_one_name(p)
        });
        let why: Vec<String> = listed
            .iter()
            .map(|h| format!("{}: {}", h.from.display(), h.why))
            .collect();
        assert_eq!(listed.len(), 3, "{why:#?}");
        assert!(
            why[0].contains("10-pin.conf: found by the installer's check, sets CPUAffinity=0"),
            "{why:#?}"
        );
        assert!(
            why[1].contains("30-ours-env.conf: found by the installer's check, EnvironmentFile=/etc/northnarrow/nn-test-absent.env is not a protected"),
            "{why:#?}"
        );
        assert!(
            why[2].contains("override.conf: found by the installer's check, EnvironmentFile=/etc/default/northnarrow-agent lies outside"),
            "{why:#?}"
        );
        assert_eq!(
            std::fs::read_dir(&ag).unwrap().count(),
            4,
            "the check moves nothing"
        );
        // installed after them: the round moves none, keeps all protected
        let installed = SystemTime::now() + std::time::Duration::from_secs(1);
        let mut kept = 0;
        let r = quarantine(
            &[root.path()],
            &host(),
            Pass {
                since: installed,
                when: AT_ROUND,
            },
            q.path(),
            1,
            |_, _| false,
            &mut |_| {
                kept += 1;
                true
            },
        );
        assert!(r.is_empty(), "{r:?}");
        // the four, and the environment file under /etc/northnarrow one names
        assert_eq!(kept, 5);
        assert_eq!(std::fs::read_dir(&ag).unwrap().count(), 4);
    }

    #[derive(Default)]
    struct FakeMap(std::collections::BTreeMap<(u64, u64), u8>);

    impl InodeMap for FakeMap {
        fn flags(&self, key: common::wire::InodeKey) -> Option<u8> {
            self.0.get(&(key.dev, key.ino)).copied()
        }
        fn register(&mut self, key: common::wire::InodeKey, flags: u8) -> anyhow::Result<()> {
            self.0.insert((key.dev, key.ino), flags);
            Ok(())
        }
        fn remove(&mut self, key: common::wire::InodeKey) -> anyhow::Result<()> {
            self.0.remove(&(key.dev, key.ino));
            Ok(())
        }
    }

    fn key(p: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(p).unwrap();
        (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        )
    }

    /// The re-review of #497 (RR1): a [`Protector`] adds WRITE|MUTATE to
    /// what a key has, refuses a link or a missing file, and takes out a
    /// key it registered once its path no longer names it — never a key
    /// it found (a boot's).
    #[test]
    fn the_protector_adds_write_protection_and_takes_out_only_its_own_stale_keys() {
        use common::wire::{FS_PROTECT_MUTATE, FS_PROTECT_READ, FS_PROTECT_WRITE};
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a.conf");
        let b = d.path().join("b.conf");
        let boot = d.path().join("boot.conf");
        for f in [&a, &b, &boot] {
            std::fs::write(f, "x").unwrap();
        }
        std::os::unix::fs::symlink(&a, d.path().join("l.conf")).unwrap();
        let registered = Registered::default();
        let mut map = FakeMap::default();
        map.0.insert(key(&boot), FS_PROTECT_READ);
        let mut p = Protector::with_map(Some(map), &registered);
        assert!(p.protect(&a) && p.protect(&b) && p.protect(&boot));
        assert!(
            !p.protect(&d.path().join("l.conf")),
            "a symlink is not held"
        );
        std::fs::hard_link(&b, d.path().join("h.conf")).unwrap();
        assert!(!p.protect(&b), "a hard link is not held");
        std::fs::remove_file(d.path().join("h.conf")).unwrap();
        assert!(p.protect(&b));
        assert!(!p.protect(&d.path().join("absent.conf")));
        let map = p.finish().unwrap();
        let wm = FS_PROTECT_WRITE | FS_PROTECT_MUTATE;
        assert_eq!(map.0.get(&key(&a)), Some(&wm));
        assert_eq!(map.0.get(&key(&boot)), Some(&(FS_PROTECT_READ | wm)));
        // the next pass: b is gone (its key taken out), boot is not kept
        // by this pass (its key, found there, stays)
        let (ka, kb, kboot) = (key(&a), key(&b), key(&boot));
        std::fs::remove_file(&b).unwrap();
        let mut map = FakeMap::default();
        for (k, f) in [(ka, wm), (kb, wm), (kboot, FS_PROTECT_READ | wm)] {
            map.0.insert(k, f);
        }
        let mut p = Protector::with_map(Some(map), &registered);
        assert!(p.protect(&a));
        let map = p.finish().unwrap();
        assert!(map.0.contains_key(&ka));
        assert!(!map.0.contains_key(&kb), "b's key taken out");
        assert!(map.0.contains_key(&kboot), "a key found there stays");
        let reg = registered.lock().unwrap();
        assert_eq!(reg.keys().cloned().collect::<Vec<_>>(), vec![a.clone()]);
    }

    /// The re-review of #497 (RR2): the installer's check lists every
    /// harmful drop-in whatever its age and moves nothing (exit 3; 0 when
    /// none); accepted, it moves them (exit 0), the harmless one left.
    #[test]
    fn the_installer_s_check_lists_then_moves_what_the_operator_accepted() {
        let prefix = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let ag = prefix
            .path()
            .join("etc/systemd/system/northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        std::fs::write(
            ag.join("override.conf"),
            "[Service]\nEnvironmentFile=-/etc/default/northnarrow-agent\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("20-log.conf"),
            "[Service]\nEnvironment=RUST_LOG=info\n",
        )
        .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            installer_check(prefix.path(), &host(), q.path(), false, 5, &mut out),
            3
        );
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(
            text.starts_with(&format!(
                "would move {}: found by the installer's check, EnvironmentFile=/etc/default/northnarrow-agent lies outside",
                ag.join("override.conf").display()
            )),
            "{text}"
        );
        assert!(ag.join("override.conf").exists(), "the check moves nothing");
        let mut out = Vec::new();
        assert_eq!(
            installer_check(prefix.path(), &host(), q.path(), true, 5, &mut out),
            0
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with(&format!("moved {} -> ", ag.join("override.conf").display())),
            "{text}"
        );
        assert!(!ag.join("override.conf").exists());
        assert!(ag.join("20-log.conf").exists());
        let mut out = Vec::new();
        assert_eq!(
            installer_check(prefix.path(), &host(), q.path(), false, 6, &mut out),
            0
        );
        assert!(out.is_empty());
    }

    /// The short re-check of #497 (RB1), with the reviewer's probe: drop-ins
    /// from before the install — a symlink to a file outside, an
    /// `EnvironmentFile=` outside /etc/northnarrow, an `ExecStartPre=` from a
    /// writable directory — are moved by no round; `preinstall_harmful`
    /// names each one for the round's signed report, and nothing is moved
    /// or registered by it. One changed after the install is not in it.
    #[test]
    fn a_harmful_drop_in_from_before_the_install_is_reported_not_moved() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let target = outside.path().join("x.conf");
        std::fs::write(&target, "[Service]\nMemoryMax=2G\n").unwrap();
        std::os::unix::fs::symlink(&target, ag.join("50-link.conf")).unwrap();
        std::fs::write(
            ag.join("60-env.conf"),
            "[Service]\nEnvironmentFile=-/etc/default/nn\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("70-exec.conf"),
            "[Service]\nExecStartPre=/var/tmp/x\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("80-log.conf"),
            "[Service]\nEnvironment=RUST_LOG=info\n",
        )
        .unwrap();
        let installed = SystemTime::now() + std::time::Duration::from_secs(60);
        // the round: since the install, nothing moved
        let moved = quarantine(
            &[root.path()],
            &host(),
            Pass {
                since: installed,
                when: AT_ROUND,
            },
            q.path(),
            1,
            |_, _| false,
            &mut |_| true,
        );
        assert!(moved.is_empty(), "{moved:?}");
        let found = preinstall_harmful(&[root.path()], &host(), installed, |_, _| false);
        let why: Vec<String> = found
            .iter()
            .map(|h| format!("{}: {}", h.from.display(), h.why))
            .collect();
        assert_eq!(found.len(), 3, "{why:#?}");
        assert!(
            why[0].contains("50-link.conf: there before the agent was installed, a symlink to"),
            "{why:#?}"
        );
        assert!(why[1].contains("60-env.conf: there before the agent was installed, EnvironmentFile=/etc/default/nn lies outside"), "{why:#?}");
        assert!(
            why[2].contains(
                "70-exec.conf: there before the agent was installed, sets ExecStartPre=/var/tmp/x"
            ),
            "{why:#?}"
        );
        assert_eq!(std::fs::read_dir(&ag).unwrap().count(), 4, "nothing moved");
        assert_eq!(std::fs::read_dir(q.path()).unwrap().count(), 0);
        // installed before them: the round's to judge, not this report's
        let before = SystemTime::now() - std::time::Duration::from_secs(60);
        assert!(preinstall_harmful(&[root.path()], &host(), before, |_, _| false).is_empty());
    }

    /// The short re-check of #497 (NB6): a protector without the map holds
    /// nothing (fail-closed) — an environment file under /etc/northnarrow
    /// is then not held, and its drop-in is quarantined.
    #[test]
    fn a_protector_without_the_map_holds_nothing() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.conf");
        std::fs::write(&f, "x").unwrap();
        let registered = Registered::default();
        let mut p = Protector::<FakeMap>::with_map(None, &registered);
        assert!(!p.protect(&f));
        assert!(p.finish().is_none());
        assert!(registered.lock().unwrap().is_empty());
    }

    /// The coordinator's decision on #497's `NN_` drop-ins: an `NN_`
    /// setting made inside a window is the operator's configuration — kept
    /// at the close, listed for its signed record (a weakening switch
    /// flagged); a loader variable stays harmful, and so does a drop-in
    /// that sets an `NN_` variable beside something harmful.
    #[test]
    fn an_nn_setting_is_kept_and_named_a_loader_variable_is_not() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        std::fs::write(
            ag.join("40-policy.conf"),
            "[Service]\nEnvironment=NN_EXEC_POLICY=audit\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("41-off.conf"),
            "[Service]\nEnvironment=\"NN_FILE_OPEN_SENSOR=tracepoint\" NN_ANTI_TAMPER_ALLOW_DEGRADED=1\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("42-loader.conf"),
            "[Service]\nEnvironment=LD_PRELOAD=/var/tmp/x.so\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("43-mixed.conf"),
            "[Service]\nEnvironment=NN_EXEC_POLICY=audit\nMemoryMax=4K\n",
        )
        .unwrap();
        let r = quarantine(
            &[root.path()],
            &host(),
            close(since),
            q.path(),
            1,
            |_, _| false,
            &mut |_| true,
        );
        let why: Vec<String> = r.iter().map(Moved::detail).collect();
        assert_eq!(r.len(), 2, "{why:#?}");
        assert!(why[0].contains("42-loader.conf: made inside the window, sets Environment=LD_PRELOAD=/var/tmp/x.so: LD_PRELOAD set"), "{why:#?}");
        assert!(
            why[1].contains("43-mixed.conf: made inside the window, sets MemoryMax=4K"),
            "{why:#?}"
        );
        assert!(ag.join("40-policy.conf").exists() && ag.join("41-off.conf").exists());
        let n = nn_settings(&[root.path()]);
        let got: Vec<(String, String, bool)> = n
            .iter()
            .map(|s| (s.name.clone(), s.value.clone(), s.weakens))
            .collect();
        assert_eq!(
            got,
            vec![
                ("NN_EXEC_POLICY".to_string(), "audit".to_string(), false),
                (
                    "NN_FILE_OPEN_SENSOR".to_string(),
                    "tracepoint".to_string(),
                    true
                ),
                (
                    "NN_ANTI_TAMPER_ALLOW_DEGRADED".to_string(),
                    "1".to_string(),
                    true
                ),
            ]
        );
        assert!(
            n[1].detail().ends_with("— a switch that weakens the agent"),
            "{n:?}"
        );
        // the installer's check: kept configuration, no refusal
        let prefix = tempfile::tempdir().unwrap();
        let pag = prefix
            .path()
            .join("etc/systemd/system/northnarrow-agent.service.d");
        std::fs::create_dir_all(&pag).unwrap();
        std::fs::copy(ag.join("40-policy.conf"), pag.join("40-policy.conf")).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            installer_check(prefix.path(), &host(), q.path(), false, 2, &mut out),
            0
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("would keep NN_EXEC_POLICY=audit set by "),
            "{text}"
        );
    }

    /// The weakening switches a drop-in of ours may set: the agent's own
    /// list and the explicit extra one (a sensor back to its fallback, the
    /// exec policy off); their other values are plain settings.
    #[test]
    fn the_weakening_switches_are_an_explicit_list() {
        for (n, v) in [
            ("NN_FILE_OPEN_SENSOR", "tracepoint"),
            ("NN_EXEC_SENSOR", "tracepoint"),
            ("NN_DNS_SENSOR", "sendmsg"),
            ("NN_EXEC_POLICY", "off"),
            ("NN_ANTI_TAMPER_ALLOW_DEGRADED", "1"),
            ("NN_AUDIT_ALLOW_UNWRITABLE", "1"),
            ("NN_DETECT_ONLY", "1"),
        ] {
            assert!(nn_weakens(n, v), "{n}={v}");
        }
        for (n, v) in [
            ("NN_FILE_OPEN_SENSOR", "lsm"),
            ("NN_EXEC_SENSOR", "lsm"),
            ("NN_DNS_SENSOR", "skb"),
            ("NN_EXEC_POLICY", "audit"),
            ("NN_EXEC_POLICY", "enforce"),
            ("NN_LAB_X", "1"),
        ] {
            assert!(!nn_weakens(n, v), "{n}={v}");
        }
        assert_eq!(WEAKENING_DROPIN_EXTRA.len(), 4);
        assert_eq!(LOADER_ENV, &["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]);
        assert_eq!(
            env_file_assignments("# c\nexport NN_A=1\nNN_B=\"x\"\n"),
            vec![
                ("NN_A".to_string(), "1".to_string()),
                ("NN_B".to_string(), "x".to_string())
            ]
        );
    }
}
