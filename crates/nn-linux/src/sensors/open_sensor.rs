//! Tappa 10.9 step 1 — userland half of the file-open sensor on LSM
//! `file_open` (`agent-ebpf/src/open_sensor.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §10).
//!
//! - [`RuleSet::build`] turns the posture's path lists, the telemetry
//!   probe directory, the home roots, the runtime directories and the
//!   credential names into the kernel's rule maps; [`OpenSensorMaps::apply`]
//!   writes them and bumps the directory-class generation.
//! - [`MountTable`] maps the root of a record's mount-relative path to a
//!   mount point, so consumers keep absolute paths. A path it cannot place,
//!   or with a component the kernel cut or could not read, is marked and
//!   never looks like an exact host path ([`path_is_exact`]).
//! - [`pump`] turns records into the events the rest of the agent reads
//!   today: `Event::FileOpen` (sensitive, critical, persistence, probe),
//!   `Event::Fim` `Opened` (credential stores, for NN-L-FIM-011..017) and
//!   `Event::MassWrite`.
//! - [`arm`] switches the kernel side on; the caller then drops the old
//!   `sys_enter_openat` tracepoint.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use common::wire::open_sensor::{
    open_class::{
        CHILDREN_PROBE, CHILD_FILES, DIR_HAS_FILES, FILE_CRITICAL, FILE_PERSIST, FILE_SENSITIVE,
        LEAF_CRED, LEAVES_CRED, SUBTREE, TREE_CARVEOUT, TREE_CRED, TREE_CRITICAL, TREE_HOME,
        TREE_PERSIST, TREE_RUNTIME,
    },
    open_reason, ChildRuleKey, OpenRecordRaw, CHILD_RULES_MAX, OPEN_CLASSIFY_DEPTH, OPEN_NAME_LEN,
    OPEN_NAME_RULES_MAX, OPEN_PATH_SLOTS, OPEN_PATH_SLOT_LEN, OPEN_RULES_MAX, OPEN_SENSOR_ARMED,
    RUNTIME_UIDS_MAX,
};
use common::wire::InodeKey;
use nn_model::telemetry::{FileCapability, FimEvent, FimOp};
use nn_model::Event;
use tracing::{info, warn};

use crate::anti_tamper::filesystem::{stat_dev_to_kernel_dev, AyaInodeKey};
use crate::sensors::reject::RejectThrottle;

/// The ring of interesting opens.
pub const OPEN_SENSOR_EVENTS_MAP: &str = "OPEN_SENSOR_EVENTS";

/// The `sys_enter_openat` program's switch (review 69): slot 0 non-zero =
/// the tracepoint emits one record per `openat`.
pub const FILE_OPEN_TP_ON_MAP: &str = "FILE_OPEN_TP_ON";

/// Turn the `sys_enter_openat` records on or off (review 69). The program
/// is attached at start in both modes. In LSM mode it stays off (the map's
/// initial value) until the LSM sensor takes over and it is detached, or
/// until a failure to arm that sensor turns it on as the fallback. Before,
/// it emitted from the start: its records filled the ring and the event
/// channel while the agent booted, and every sensor's events waited.
pub fn set_tracepoint_emitting(ebpf: &mut Ebpf, on: bool) -> Result<()> {
    let map = ebpf
        .map_mut(FILE_OPEN_TP_ON_MAP)
        .ok_or_else(|| anyhow!("{FILE_OPEN_TP_ON_MAP} missing from the eBPF object"))?;
    let mut switch: Array<&mut MapData, u32> = Array::try_from(map)?;
    switch.set(0, u32::from(on), 0)?;
    Ok(())
}

/// Credential-store names (Q1, review 54), the kernel side of the path
/// fragments NN-L-FIM-011..017 match: `(name, parent name or "" for any,
/// bits)`. Directory names mark trees (`TREE_CRED`) or directories whose
/// leaves are checked (`LEAVES_CRED`); leaf names are `LEAF_CRED`, read
/// in those directories and, for the browser stores, in home trees.
/// Names are cut at 31 bytes, as the kernel cuts them.
pub const CRED_NAME_RULES: &[(&str, &str, u32)] = &[
    (".aws", "", LEAVES_CRED),
    (".docker", "", LEAVES_CRED),
    ("gcloud", "", LEAVES_CRED),
    ("docker", "", LEAVES_CRED),
    (".gnupg", "", TREE_CRED),
    (".password-store", "", TREE_CRED),
    (".azure", "", TREE_CRED),
    ("legacy_credentials", "gcloud", TREE_CRED),
    ("credentials", ".aws", LEAF_CRED),
    ("config", ".aws", LEAF_CRED),
    ("config.json", ".docker", LEAF_CRED),
    ("credentials.db", "gcloud", LEAF_CRED),
    ("access_tokens.db", "gcloud", LEAF_CRED),
    ("application_default_credentials.json", "gcloud", LEAF_CRED),
    ("credentials.json", "docker", LEAF_CRED),
    ("Login Data", "", LEAF_CRED),
    ("logins.json", "", LEAF_CRED),
    ("key4.db", "", LEAF_CRED),
    ("key3.db", "", LEAF_CRED),
    ("signons.sqlite", "", LEAF_CRED),
];

/// `ChildRuleKey` for aya (the orphan rule: same bytes, local type).
#[repr(transparent)]
#[derive(Clone, Copy)]
struct AyaChildKey(ChildRuleKey);
// SAFETY: `ChildRuleKey` is `#[repr(C)]`, two u64 and 32 bytes, no
// padding; every bit pattern is valid.
unsafe impl aya::Pod for AyaChildKey {}

/// A NUL-padded rule name, cut at 31 bytes like the kernel's read.
pub fn name32(s: &str) -> [u8; OPEN_NAME_LEN] {
    let mut k = [0u8; OPEN_NAME_LEN];
    let b = s.as_bytes();
    let n = b.len().min(OPEN_NAME_LEN - 1);
    k[..n].copy_from_slice(&b[..n]);
    k
}

fn name_key(name: &str, parent: &str) -> [u8; 2 * OPEN_NAME_LEN] {
    let mut k = [0u8; 2 * OPEN_NAME_LEN];
    k[..OPEN_NAME_LEN].copy_from_slice(&name32(name));
    if !parent.is_empty() {
        k[OPEN_NAME_LEN..].copy_from_slice(&name32(parent));
    }
    k
}

fn key_of(meta: &std::fs::Metadata) -> InodeKey {
    InodeKey {
        dev: stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    }
}

/// What the agent registers in the kernel.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleSet {
    pub inodes: HashMap<InodeKey, u32>,
    pub children: HashMap<ChildRuleKey, u32>,
    pub names: HashMap<[u8; 2 * OPEN_NAME_LEN], u32>,
    pub runtime: HashMap<InodeKey, u32>,
    /// Rules that could not be registered (a file two levels below a
    /// missing directory): logged, not fatal.
    pub skipped: Vec<String>,
    /// Carve-outs refused because a symbolic link is on their path, with
    /// the link (external audit POS-010, lab PR 198): a WARN when new.
    pub refused: Vec<String>,
}

/// The inputs of [`RuleSet::build`].
#[derive(Debug, Clone, Default)]
pub struct RuleInputs {
    pub sensitive: Vec<String>,
    pub critical: Vec<String>,
    pub persistence: Vec<String>,
    /// Mass-write carve-outs (`/run/systemd/`, the journal, the
    /// operator's `mass-write-carveout.local`); pseudo-filesystems are
    /// carved out by superblock magic in the kernel.
    pub carveout: Vec<String>,
    pub probe_dir: PathBuf,
    pub homes: Vec<PathBuf>,
    /// `/run/user/<uid>` mount roots and their uid.
    pub runtime: Vec<(PathBuf, u32)>,
}

impl RuleInputs {
    /// The agent's own lists, the probe directory, `/root` and the home
    /// of every account ([`home_roots`]), and the runtime directories
    /// under `/run/user`.
    pub fn from_host(carveout_extras: &[String]) -> Self {
        use crate::posture::triggers::{
            CRITICAL_FILES_PREFIXES, MASS_WRITE_CARVEOUT_PREFIXES, PERSISTENCE_PREFIXES,
            SENSITIVE_FILES,
        };
        let own = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut carveout = own(MASS_WRITE_CARVEOUT_PREFIXES);
        carveout.extend(carveout_extras.iter().cloned());
        RuleInputs {
            sensitive: own(SENSITIVE_FILES),
            critical: own(CRITICAL_FILES_PREFIXES),
            persistence: own(PERSISTENCE_PREFIXES),
            carveout,
            probe_dir: PathBuf::from(crate::telemetry_probe::PROBE_DIR),
            homes: home_roots(&std::fs::read_to_string("/etc/passwd").unwrap_or_default()),
            runtime: runtime_dirs(Path::new("/run/user")),
        }
    }
}

/// External audit SNS-010: declared homes that are directories every
/// account shares, never one account's tree.
const SHARED_HOMES: &[&str] = &[
    "/",
    "/nonexistent",
    "/home",
    "/mnt",
    "/media",
    "/opt",
    "/run",
    "/srv",
    "/tmp",
    "/usr",
    "/usr/games",
    "/usr/local",
    "/usr/share",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/lib/misc",
    "/var/log",
    "/var/mail",
    "/var/run",
    "/var/spool",
    "/var/tmp",
];

/// External audit SNS-010: trees no account's home lies in — programs and
/// libraries, configuration, kernel interfaces (`/dev/null`, `/proc`) and
/// the empty chroots under `/var/empty`.
const SYSTEM_TREES: &[&str] = &[
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/proc",
    "/sbin",
    "/sys",
    "/usr/bin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/sbin",
    "/var/empty",
];

/// External audit SNS-010: whether `home` is a shared system directory
/// ([`SHARED_HOMES`], [`SYSTEM_TREES`]) rather than one account's home.
/// Compared by component, so `/var/lib/` and `//var/lib` are `/var/lib`.
pub fn is_shared_system_dir(home: &Path) -> bool {
    SHARED_HOMES.iter().any(|s| home == Path::new(s))
        || SYSTEM_TREES.iter().any(|t| home.starts_with(t))
}

/// The home of every `/etc/passwd` account, each once, and `/root`.
/// External audit SNS-010: it was `/root` and the accounts with uid 1000 to
/// 65533 only — uid 0's declared home and the service accounts' homes
/// (Jenkins, GitLab Runner, PostgreSQL) had no `TREE_HOME` name checks.
/// Now every uid except the overflow ones (`nobody`/`nfsnobody`, 65534,
/// 4294967294, 4294967295, and any account named `nobody`), unless the
/// home is a shared system directory ([`is_shared_system_dir`]).
/// [`RuleSet::build`] keeps the ones that resolve to an existing directory
/// that is not one either.
pub fn home_roots(passwd: &str) -> Vec<PathBuf> {
    const OVERFLOW_UIDS: [u32; 3] = [65534, 4_294_967_294, 4_294_967_295];
    let mut out = vec![PathBuf::from("/root")];
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        if OVERFLOW_UIDS.contains(&uid) || f[0] == "nobody" || !f[5].starts_with('/') {
            continue;
        }
        let p = PathBuf::from(f[5]);
        if is_shared_system_dir(&p) || out.contains(&p) {
            continue;
        }
        out.push(p);
    }
    out
}

/// `/run/user/<uid>` directories and their uid.
pub fn runtime_dirs(base: &Path) -> Vec<(PathBuf, u32)> {
    let Ok(rd) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| {
            let uid = e.file_name().to_str()?.parse::<u32>().ok()?;
            Some((e.path(), uid))
        })
        .collect()
}

impl RuleSet {
    pub fn build(inputs: &RuleInputs) -> Self {
        let mut set = RuleSet::default();
        for p in &inputs.sensitive {
            set.add_path(p, FILE_SENSITIVE, 0);
        }
        for p in &inputs.critical {
            set.add_path(p, FILE_CRITICAL, TREE_CRITICAL);
        }
        for p in &inputs.persistence {
            set.add_path(p, FILE_PERSIST, TREE_PERSIST);
        }
        for p in &inputs.carveout {
            set.add_carveout(p);
        }
        let probe = format!("{}/", inputs.probe_dir.display());
        set.add_path(&probe, 0, CHILDREN_PROBE);
        for h in &inputs.homes {
            // External audit SNS-010: a home that resolves (a symbolic
            // link, `..`) into a shared system directory is not one
            // account's tree either.
            let Ok(real) = std::fs::canonicalize(h) else {
                continue;
            };
            if is_shared_system_dir(&real) {
                continue;
            }
            if let Ok(m) = std::fs::metadata(&real) {
                if m.is_dir() {
                    *set.inodes.entry(key_of(&m)).or_default() |= TREE_HOME;
                }
            }
        }
        for (dir, uid) in &inputs.runtime {
            if let Ok(m) = std::fs::metadata(dir) {
                let k = key_of(&m);
                *set.inodes.entry(k).or_default() |= TREE_RUNTIME;
                set.runtime.insert(k, *uid);
            }
        }
        for (name, parent, bits) in CRED_NAME_RULES {
            *set.names.entry(name_key(name, parent)).or_default() |= bits;
        }
        set
    }

    /// One mass-write carve-out: a directory rule (its subtree), or, while
    /// it is missing, a rule under its nearest existing ancestor by the
    /// first missing name. External audit POS-010 (lab PR 198): the path
    /// is walked from `/` without following a symbolic link. `metadata`
    /// followed them, every minute: a user who replaced the directory of a
    /// signed carve-out under their home (`~/.claude/`) with a link to `~`
    /// or `/` moved the carve-out to that tree (in a sticky directory such
    /// as `/tmp`, `fs.protected_symlinks` keeps root from following another
    /// user's link, where it is on). A link on the way refuses the
    /// carve-out (the tree is counted); a file or a non-directory on the
    /// way is `skipped`.
    fn add_carveout(&mut self, rule: &str) {
        match place_carveout(Path::new(rule)) {
            Ok(CarveoutPlace::Dir(m)) => {
                *self.inodes.entry(key_of(&m)).or_default() |= TREE_CARVEOUT;
            }
            Ok(CarveoutPlace::Missing {
                parent,
                name,
                direct,
            }) => {
                let bits = if direct {
                    TREE_CARVEOUT
                } else {
                    TREE_CARVEOUT & SUBTREE
                };
                let key = ChildRuleKey {
                    parent: key_of(&parent),
                    name: name32(&name),
                };
                *self.children.entry(key).or_default() |= bits;
            }
            Ok(CarveoutPlace::Link(at)) => self.refused.push(format!(
                "{rule}: `{}` is a symbolic link — a carve-out never follows one",
                at.display()
            )),
            Ok(CarveoutPlace::NotDir) | Err(_) => self.skipped.push(rule.to_string()),
        }
    }

    /// One path rule. The posture's lists are path prefixes; the kernel
    /// classifies by inode, so `dir/` (or an existing directory) is a
    /// directory rule (`tree_bits` for its children or subtree) and
    /// anything else a file rule (`file_bits`). A list with no file rules
    /// (the mass-write carve-outs) reads every entry as a directory, with
    /// or without the final `/`. A missing path is registered under its
    /// nearest existing ancestor by the first missing name, so it is
    /// caught when it appears. What the kernel cannot express (a
    /// carve-out naming a file) goes to `skipped`.
    fn add_path(&mut self, rule: &str, file_bits: u32, tree_bits: u32) {
        let is_dir = (rule.ends_with('/') && rule.len() > 1) || file_bits == 0;
        let path = Path::new(if rule.len() > 1 {
            rule.trim_end_matches('/')
        } else {
            rule
        });
        if let Ok(m) = std::fs::metadata(path) {
            // A path that turned out to be a directory gets the tree bits.
            let b = if m.is_dir() { tree_bits } else { file_bits };
            if b == 0 {
                self.skipped.push(rule.to_string());
                return;
            }
            *self.inodes.entry(key_of(&m)).or_default() |= b;
            // The kernel looks a file's own rule up only in directories
            // marked as holding some (the file's real parent).
            if !m.is_dir() {
                let parent = std::fs::canonicalize(path)
                    .ok()
                    .and_then(|real| real.parent().and_then(|p| std::fs::metadata(p).ok()));
                if let Some(pm) = parent {
                    *self.inodes.entry(key_of(&pm)).or_default() |= DIR_HAS_FILES;
                }
            }
            return;
        }
        if (if is_dir { tree_bits } else { file_bits }) == 0 {
            return;
        }
        // Nearest existing ancestor and the first missing component.
        let mut missing = path;
        let mut parent = path.parent();
        while let Some(p) = parent {
            if let Ok(m) = std::fs::metadata(p) {
                let Some(name) = missing.file_name().and_then(|n| n.to_str()) else {
                    return;
                };
                let direct = missing == path;
                // Deeper than one missing level only what passes to a
                // whole subtree still means the right thing.
                let child_bits = match (is_dir, direct) {
                    (true, true) => tree_bits,
                    (false, true) => file_bits,
                    (true, false) => tree_bits & SUBTREE,
                    (false, false) => 0,
                };
                if child_bits == 0 {
                    self.skipped.push(rule.to_string());
                    return;
                }
                let key = ChildRuleKey {
                    parent: key_of(&m),
                    name: name32(name),
                };
                *self.children.entry(key).or_default() |= child_bits;
                if !is_dir {
                    *self.inodes.entry(key_of(&m)).or_default() |= CHILD_FILES;
                }
                return;
            }
            missing = p;
            parent = p.parent();
        }
        self.skipped.push(rule.to_string());
    }
}

/// Where a carve-out lands ([`RuleSet::add_carveout`]).
#[derive(Debug)]
enum CarveoutPlace {
    /// The directory itself.
    Dir(std::fs::Metadata),
    /// Its nearest existing ancestor and the first missing name below it;
    /// `direct` when that name is the carve-out's own.
    Missing {
        parent: std::fs::Metadata,
        name: String,
        direct: bool,
    },
    /// No directory rule can hold it: a file, a non-directory or a `..`
    /// on the way, a name that is not UTF-8.
    NotDir,
    /// A symbolic link at this prefix of the path.
    Link(PathBuf),
}

/// Walk `path` from `/`, one component at a time, each opened `O_PATH |
/// O_NOFOLLOW` below the last and checked on its own fd (no window
/// between the check and the inode taken).
fn place_carveout(path: &Path) -> std::io::Result<CarveoutPlace> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let open = |at: libc::c_int, name: &std::ffi::CStr| -> std::io::Result<std::fs::File> {
        // SAFETY: openat on a NUL-terminated name; the fd is ours on success.
        let fd = unsafe {
            libc::openat(
                at,
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a fresh fd returned by openat.
        Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    };
    let mut names = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => names.push(n),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return Ok(CarveoutPlace::NotDir),
        }
    }
    let mut cur = open(libc::AT_FDCWD, c"/")?;
    let mut walked = PathBuf::from("/");
    for (i, n) in names.iter().enumerate() {
        walked.push(n);
        let c = CString::new(n.as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let next = match open(cur.as_raw_fd(), &c) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = n.to_str() else {
                    return Ok(CarveoutPlace::NotDir);
                };
                return Ok(CarveoutPlace::Missing {
                    parent: cur.metadata()?,
                    name: name.to_string(),
                    direct: i + 1 == names.len(),
                });
            }
            Err(e) => return Err(e),
        };
        let m = next.metadata()?;
        if m.file_type().is_symlink() {
            return Ok(CarveoutPlace::Link(walked));
        }
        if !m.is_dir() {
            return Ok(CarveoutPlace::NotDir);
        }
        cur = next;
    }
    Ok(CarveoutPlace::Dir(cur.metadata()?))
}

/// External audit POS-010 (lab PR 198): a WARN for each carve-out `next`
/// refuses that `previous` did not (at boot every one; then once, not at
/// every refresh).
pub fn warn_refused_carveouts(previous: Option<&RuleSet>, next: &RuleSet) {
    for r in &next.refused {
        if previous.is_some_and(|p| p.refused.contains(r)) {
            continue;
        }
        warn!(
            carveout = %r,
            "file-open sensor: mass-write carve-out NOT applied — a symbolic link on its path \
             (the mass-write arm counts that tree)"
        );
    }
}

/// Owned handles on the sensor's rule maps (taken out of the object, so a
/// task can refresh them).
pub struct OpenSensorMaps {
    rules: BpfHashMap<MapData, AyaInodeKey, u32>,
    children: BpfHashMap<MapData, AyaChildKey, u32>,
    names: BpfHashMap<MapData, [u8; 2 * OPEN_NAME_LEN], u32>,
    runtime: BpfHashMap<MapData, AyaInodeKey, u32>,
    generation: Array<MapData, u32>,
    /// External audit SNS-011: the generation this process last wrote
    /// (0: none yet), so a bump never goes back below it.
    last_generation: u32,
    armed: Array<MapData, u32>,
    depth_capped: PerCpuArray<MapData, u64>,
}

/// External audit SNS-011: the slot that holds the directory-class
/// generation (`DIR_CLASS_GEN`), as [`bump_generation_in`] reads and writes
/// it (a trait, so a test can stand in a map that fails).
pub trait GenerationSlot {
    fn read_generation(&self) -> Result<u32>;
    fn write_generation(&mut self, value: u32) -> Result<()>;
}

impl GenerationSlot for Array<MapData, u32> {
    fn read_generation(&self) -> Result<u32> {
        Ok(self.get(&0, 0)?)
    }
    fn write_generation(&mut self, value: u32) -> Result<()> {
        Ok(self.set(0, value, 0)?)
    }
}

/// External audit SNS-011: the generation after `read` (the slot's value)
/// when this process last wrote `last_written` (0: never). The later of the
/// two, in serial-number order (RFC 1982: the slot wraps), plus one, and
/// never 0, the slot's value before any rule was written. A slot read back
/// lower than this process wrote it — something else reset it — does not
/// take the generation back to a value classes may still be cached under.
pub fn next_generation(read: u32, last_written: u32) -> u32 {
    let ahead = last_written != 0 && (last_written.wrapping_sub(read) as i32) > 0;
    match (if ahead { last_written } else { read }).wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

/// External audit SNS-011: invalidate every cached directory class. A read
/// that fails is an error (the bump used to read 0 and write 1, which could
/// take the generation back); nothing is written then. The kernel bumps the
/// same slot on a directory rename without coordination
/// (`agent-ebpf/src/open_sensor.rs`, `bump_generation`): the only property
/// needed is that the value changes after the rules are written, and a
/// kernel bump between this read and this write may merge with this one
/// (both write N + 1). That is accepted: the rules were written before the
/// read, so every class cached before the write is still stale, and a
/// class cached in between was built under the new rules. An atomic add in
/// the kernel would cost verifier budget in `fim_file_open_sensor` for
/// nothing more.
pub fn bump_generation_in(slot: &mut impl GenerationSlot, last_written: &mut u32) -> Result<()> {
    let read = slot
        .read_generation()
        .map_err(|e| anyhow!("reading DIR_CLASS_GEN: {e:#}"))?;
    let next = next_generation(read, *last_written);
    slot.write_generation(next)?;
    *last_written = next;
    Ok(())
}

fn take(ebpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map> {
    ebpf.take_map(name)
        .ok_or_else(|| anyhow!("map `{name}` missing from eBPF object"))
}

impl OpenSensorMaps {
    pub fn take(ebpf: &mut Ebpf) -> Result<Self> {
        Ok(OpenSensorMaps {
            rules: BpfHashMap::try_from(take(ebpf, "OPEN_RULES")?)?,
            children: BpfHashMap::try_from(take(ebpf, "CHILD_RULES")?)?,
            names: BpfHashMap::try_from(take(ebpf, "OPEN_NAME_RULES")?)?,
            runtime: BpfHashMap::try_from(take(ebpf, "RUNTIME_UIDS")?)?,
            generation: Array::try_from(take(ebpf, "DIR_CLASS_GEN")?)?,
            last_generation: 0,
            armed: Array::try_from(take(ebpf, "OPEN_SENSOR")?)?,
            depth_capped: PerCpuArray::try_from(take(ebpf, "OPEN_DEPTH_CAPPED")?)?,
        })
    }

    /// Write `set` over `previous` ([`apply_rules`]): every rule that
    /// fits, the generation bumped whatever failed.
    pub fn apply(&mut self, set: &RuleSet, previous: Option<&RuleSet>) -> Applied {
        apply_rules(self, set, previous)
    }

    /// External audit EBPF-011: classifications whose walk stopped at the
    /// depth cap since the sensor loaded (all CPUs).
    pub fn depth_capped_total(&self) -> Result<u64> {
        Ok(self.depth_capped.get(&0, 0)?.iter().sum())
    }

    /// Invalidate every cached directory class ([`bump_generation_in`]).
    pub fn bump_generation(&mut self) -> Result<()> {
        bump_generation_in(&mut self.generation, &mut self.last_generation)
    }

    /// Switch the kernel side on (or off): from now on the FIM
    /// `file_open` observer classifies every open.
    pub fn arm(&mut self, on: bool) -> Result<()> {
        self.armed
            .set(0, if on { OPEN_SENSOR_ARMED } else { 0 }, 0)?;
        Ok(())
    }
}

/// A rule already absent is removed (`ENOENT`).
fn removed(r: std::result::Result<(), aya::maps::MapError>) -> Result<()> {
    match r {
        Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

impl RuleMaps for OpenSensorMaps {
    fn insert_inode(&mut self, k: InodeKey, v: u32) -> Result<()> {
        Ok(self.rules.insert(AyaInodeKey(k), v, 0)?)
    }
    fn remove_inode(&mut self, k: InodeKey) -> Result<()> {
        removed(self.rules.remove(&AyaInodeKey(k)))
    }
    fn insert_child(&mut self, k: ChildRuleKey, v: u32) -> Result<()> {
        Ok(self.children.insert(AyaChildKey(k), v, 0)?)
    }
    fn remove_child(&mut self, k: ChildRuleKey) -> Result<()> {
        removed(self.children.remove(&AyaChildKey(k)))
    }
    fn insert_name(&mut self, k: [u8; 2 * OPEN_NAME_LEN], v: u32) -> Result<()> {
        Ok(self.names.insert(k, v, 0)?)
    }
    fn remove_name(&mut self, k: [u8; 2 * OPEN_NAME_LEN]) -> Result<()> {
        removed(self.names.remove(&k))
    }
    fn insert_runtime(&mut self, k: InodeKey, uid: u32) -> Result<()> {
        Ok(self.runtime.insert(AyaInodeKey(k), uid, 0)?)
    }
    fn remove_runtime(&mut self, k: InodeKey) -> Result<()> {
        removed(self.runtime.remove(&AyaInodeKey(k)))
    }
    fn bump_generation(&mut self) -> Result<()> {
        OpenSensorMaps::bump_generation(self)
    }
}

/// The kernel's rule maps as [`apply_rules`] writes them (a trait, so a
/// test can stand in a map that fills up).
pub trait RuleMaps {
    fn insert_inode(&mut self, k: InodeKey, v: u32) -> Result<()>;
    fn remove_inode(&mut self, k: InodeKey) -> Result<()>;
    fn insert_child(&mut self, k: ChildRuleKey, v: u32) -> Result<()>;
    fn remove_child(&mut self, k: ChildRuleKey) -> Result<()>;
    fn insert_name(&mut self, k: [u8; 2 * OPEN_NAME_LEN], v: u32) -> Result<()>;
    fn remove_name(&mut self, k: [u8; 2 * OPEN_NAME_LEN]) -> Result<()>;
    fn insert_runtime(&mut self, k: InodeKey, uid: u32) -> Result<()>;
    fn remove_runtime(&mut self, k: InodeKey) -> Result<()>;
    fn bump_generation(&mut self) -> Result<()>;
}

/// What [`apply_rules`] did.
#[derive(Debug, Default)]
pub struct Applied {
    /// Rules written (new or updated).
    pub inserted: usize,
    /// Rules refused (a full map), and stale rules that could not be
    /// removed.
    pub failed: usize,
    /// The generation could not be bumped: cached classes may be stale.
    pub generation_failed: bool,
    /// The first error, for the log.
    pub first_error: Option<String>,
    /// What the maps hold now: `set` without the refused rules, plus the
    /// stale rules still there. The next refresh writes the difference
    /// against this, so a refused rule is tried again and a stale one
    /// removed again.
    pub in_maps: RuleSet,
}

impl Applied {
    pub fn degraded(&self) -> bool {
        self.failed > 0 || self.generation_failed
    }

    fn fail(&mut self, e: anyhow::Error) {
        self.failed += 1;
        if self.first_error.is_none() {
            self.first_error = Some(format!("{e:#}"));
        }
    }
}

/// Order of the inode rules when a map cannot hold them all: the posture's
/// own paths (sensitive, critical, persistence files and trees, carve-outs,
/// the probe) first, then home trees, then runtime directories.
fn insert_rank(bits: u32) -> u8 {
    if bits & !(TREE_HOME | TREE_RUNTIME) != 0 {
        0
    } else if bits & TREE_HOME != 0 {
        1
    } else {
        2
    }
}

/// External audit SNS-007: write `set` where `previous` was, without
/// stopping at the first refused rule. Stale rules (in `previous`, not in
/// `set`) are removed first, so they free room; then the inode rules go in
/// by [`insert_rank`], then child, name and runtime-owner rules (a runtime
/// owner only where its directory rule went in). The generation is bumped
/// whatever failed, so no class cached under the old rules survives.
pub fn apply_rules(maps: &mut impl RuleMaps, set: &RuleSet, previous: Option<&RuleSet>) -> Applied {
    let mut out = Applied {
        in_maps: RuleSet {
            skipped: set.skipped.clone(),
            refused: set.refused.clone(),
            ..RuleSet::default()
        },
        ..Applied::default()
    };
    if let Some(prev) = previous {
        for (k, v) in prev
            .inodes
            .iter()
            .filter(|(k, _)| !set.inodes.contains_key(k))
        {
            if let Err(e) = maps.remove_inode(*k) {
                out.fail(e);
                out.in_maps.inodes.insert(*k, *v);
            }
        }
        for (k, v) in prev
            .children
            .iter()
            .filter(|(k, _)| !set.children.contains_key(k))
        {
            if let Err(e) = maps.remove_child(*k) {
                out.fail(e);
                out.in_maps.children.insert(*k, *v);
            }
        }
        for (k, v) in prev
            .names
            .iter()
            .filter(|(k, _)| !set.names.contains_key(*k))
        {
            if let Err(e) = maps.remove_name(*k) {
                out.fail(e);
                out.in_maps.names.insert(*k, *v);
            }
        }
        for (k, v) in prev
            .runtime
            .iter()
            .filter(|(k, _)| !set.runtime.contains_key(k))
        {
            if let Err(e) = maps.remove_runtime(*k) {
                out.fail(e);
                out.in_maps.runtime.insert(*k, *v);
            }
        }
    }
    let mut inodes: Vec<(&InodeKey, &u32)> = set.inodes.iter().collect();
    inodes.sort_by_key(|(k, v)| (insert_rank(**v), k.dev, k.ino));
    for (k, v) in inodes {
        match maps.insert_inode(*k, *v) {
            Ok(()) => {
                out.inserted += 1;
                out.in_maps.inodes.insert(*k, *v);
            }
            Err(e) => out.fail(e),
        }
    }
    let mut children: Vec<(&ChildRuleKey, &u32)> = set.children.iter().collect();
    children.sort_by_key(|(k, _)| (k.parent.dev, k.parent.ino, k.name));
    for (k, v) in children {
        match maps.insert_child(*k, *v) {
            Ok(()) => {
                out.inserted += 1;
                out.in_maps.children.insert(*k, *v);
            }
            Err(e) => out.fail(e),
        }
    }
    let mut names: Vec<(&[u8; 2 * OPEN_NAME_LEN], &u32)> = set.names.iter().collect();
    names.sort();
    for (k, v) in names {
        match maps.insert_name(*k, *v) {
            Ok(()) => {
                out.inserted += 1;
                out.in_maps.names.insert(*k, *v);
            }
            Err(e) => out.fail(e),
        }
    }
    let mut runtime: Vec<(&InodeKey, &u32)> = set
        .runtime
        .iter()
        .filter(|(k, _)| out.in_maps.inodes.contains_key(k))
        .collect();
    runtime.sort_by_key(|(k, _)| (k.dev, k.ino));
    for (k, uid) in runtime {
        match maps.insert_runtime(*k, *uid) {
            Ok(()) => {
                out.inserted += 1;
                out.in_maps.runtime.insert(*k, *uid);
            }
            Err(e) => out.fail(e),
        }
    }
    if let Err(e) = maps.bump_generation() {
        out.generation_failed = true;
        if out.first_error.is_none() {
            out.first_error = Some(format!("generation bump: {e:#}"));
        }
    }
    out
}

/// Whether the rules in the maps are complete, tracked across refreshes so
/// a lasting failure is reported once ([`RuleHealth::note`]).
#[derive(Debug, Default)]
pub struct RuleHealth {
    failing: Option<usize>,
}

/// What a refresh changed in [`RuleHealth`].
#[derive(Debug, PartialEq, Eq)]
pub enum RuleHealthChange {
    /// Rules were refused (or the generation not bumped) after a complete
    /// write: ERROR and one signed `subsystem_degraded`.
    Degraded,
    /// Still refused, a different number of them: WARN.
    Changed,
    /// Complete again: INFO.
    Recovered,
    /// Nothing new to say.
    Same,
}

impl RuleHealth {
    pub fn note(&mut self, a: &Applied) -> RuleHealthChange {
        let now = a.degraded().then_some(a.failed);
        let change = match (self.failing, now) {
            (None, Some(_)) => RuleHealthChange::Degraded,
            (Some(_), None) => RuleHealthChange::Recovered,
            (Some(was), Some(is)) if was != is => RuleHealthChange::Changed,
            _ => RuleHealthChange::Same,
        };
        self.failing = now;
        change
    }
}

/// The map capacities the kernel object declares, for the log.
pub const RULE_CAPACITY: (u32, u32, u32, u32) = (
    OPEN_RULES_MAX,
    CHILD_RULES_MAX,
    OPEN_NAME_RULES_MAX,
    RUNTIME_UIDS_MAX,
);

pub fn take_ringbuf(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    RingBuf::try_from(take(ebpf, OPEN_SENSOR_EVENTS_MAP)?)
        .map_err(|e| anyhow!("{OPEN_SENSOR_EVENTS_MAP} is not a RINGBUF: {e}"))
}

// ───────────────────────────── paths ─────────────────────────────

/// Filesystem roots → mount points, from `/proc/self/mountinfo` and a
/// `stat()` of each mount point (the key the kernel records for the top
/// of a path walk).
///
/// External audit SNS-004: the table was re-read on a miss only, so a hit
/// was never checked again. An anonymous device is reused (a tmpfs
/// unmounted and another mounted elsewhere gets the same `0:N` and root
/// inode 1), and on a quiet host the old mount point kept naming the new
/// filesystem's files. A hit is now checked:
/// - the open `mountinfo` is polled (`POLLPRI`, no wait) at every lookup:
///   the kernel flags it whenever a mount or an unmount changes this
///   namespace's table. After a change the table is re-read, at most once
///   per [`MOUNT_REFRESH_MIN`]; until then a hit is answered only while a
///   `stat()` of its mount point still shows that root, and dropped (the
///   path is then unplaced, never another mount's) when it does not;
/// - whatever the poll says, the table is re-read when it is older than
///   [`MOUNT_HIT_TTL`].
///
/// The kernel's record names the filesystem root, not the mount: a record
/// queued before an unmount and read after the device was reused is put
/// on the new mount point (a window of the ring's latency; a mount id in
/// the record would be a kernel change).
#[derive(Debug)]
pub struct MountTable {
    roots: HashMap<(u64, u64), String>,
    loaded: Option<Instant>,
    /// The `mountinfo` a refresh reads (`/proc/self/mountinfo`; a fixture
    /// in tests).
    source: PathBuf,
    /// `source`, open for the change poll (`None`: not opened, or not
    /// pollable; the TTL alone then bounds the table's age).
    watch: Option<std::fs::File>,
    /// A change was polled and the table not re-read yet.
    changed: bool,
}

impl Default for MountTable {
    fn default() -> Self {
        MountTable {
            roots: HashMap::new(),
            loaded: None,
            source: PathBuf::from("/proc/self/mountinfo"),
            watch: None,
            changed: false,
        }
    }
}

/// Re-read the table, on a miss or after a polled change, at most this
/// often.
const MOUNT_REFRESH_MIN: Duration = Duration::from_secs(2);

/// External audit SNS-004: re-read the table when it is older than this,
/// whatever the lookups found.
pub const MOUNT_HIT_TTL: Duration = Duration::from_secs(30);

/// Whether the kernel flagged a change of the mount table `mountinfo`
/// shows since the last poll (`POLLPRI`; the poll itself clears it). A
/// regular file never reports one.
fn mounts_changed(mountinfo: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    let mut p = libc::pollfd {
        fd: mountinfo.as_raw_fd(),
        events: libc::POLLPRI,
        revents: 0,
    };
    // SAFETY: one valid, initialised pollfd for a descriptor `mountinfo`
    // keeps open; a zero timeout never blocks.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n > 0 && p.revents & (libc::POLLPRI | libc::POLLERR) != 0
}

impl MountTable {
    pub fn load() -> Self {
        Self::load_from(Path::new("/proc/self/mountinfo"))
    }

    /// [`Self::load`] from another `mountinfo` (tests: a fixture file).
    pub fn load_from(source: &Path) -> Self {
        let mut t = MountTable {
            source: source.to_path_buf(),
            watch: std::fs::File::open(source).ok(),
            ..MountTable::default()
        };
        t.refresh();
        t
    }

    pub fn refresh(&mut self) {
        let text = std::fs::read_to_string(&self.source).unwrap_or_default();
        let mut roots = HashMap::new();
        for mp in mount_points(&text) {
            if let Ok(m) = std::fs::metadata(&mp) {
                let k = key_of(&m);
                // The shortest mount point wins (a bind mount of the same
                // root elsewhere is an alias).
                roots
                    .entry((k.dev, k.ino))
                    .and_modify(|cur: &mut String| {
                        if mp.len() < cur.len() {
                            *cur = mp.clone();
                        }
                    })
                    .or_insert(mp);
            }
        }
        self.roots = roots;
        self.loaded = Some(Instant::now());
        self.changed = false;
    }

    /// Whether the mount point `mp` still shows the filesystem root `root`.
    fn still_shows(mp: &str, root: (u64, u64)) -> bool {
        std::fs::metadata(mp).is_ok_and(|m| {
            let k = key_of(&m);
            (k.dev, k.ino) == root
        })
    }

    /// Absolute path of `rel` (mount-relative, starting with `/`) under
    /// the filesystem root `root`: re-reading the table on a miss, after a
    /// change of the mounts, and when it is older than [`MOUNT_HIT_TTL`].
    pub fn absolute(&mut self, root: (u64, u64), rel: &str) -> Option<String> {
        if root == (0, 0) {
            return None;
        }
        if self.watch.as_ref().is_some_and(mounts_changed) {
            self.changed = true;
        }
        let hit = self.roots.contains_key(&root);
        let age = self.loaded.map(|t| t.elapsed());
        let refresh = match age {
            None => true,
            Some(age) => {
                age >= MOUNT_HIT_TTL || ((!hit || self.changed) && age >= MOUNT_REFRESH_MIN)
            }
        };
        if refresh {
            self.refresh();
        } else if hit && self.changed {
            if let Some(mp) = self.roots.get(&root) {
                if !Self::still_shows(mp, root) {
                    self.roots.remove(&root);
                }
            }
        }
        let mp = self.roots.get(&root)?;
        Some(if mp == "/" {
            rel.to_string()
        } else {
            format!("{mp}{rel}")
        })
    }
}

/// The mount points of a `mountinfo` text (field 5, octal escapes
/// decoded).
pub fn mount_points(mountinfo: &str) -> Vec<String> {
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(unescape_octal)
        .collect()
}

pub use crate::path_text::unescape_octal;
/// The text of the paths this sensor renders, shared with their readers:
/// `crate::path_text`'s since R04b (lab PR 241), named here as before.
pub use crate::path_text::{path_is_exact, CUT_MARK, UNREAD_COMPONENT};

/// The record's path components, leaf → root. External audit SNS-006: a
/// name of `OPEN_PATH_SLOT_LEN - 1` bytes may have been cut (a longer name
/// reads the same) and gets [`CUT_MARK`]; an empty slot is a read that
/// failed, [`UNREAD_COMPONENT`].
fn components(r: &OpenRecordRaw) -> Vec<String> {
    (0..(r.path_n as usize).min(OPEN_PATH_SLOTS))
        .map(|i| {
            let slot = &r.path[i * OPEN_PATH_SLOT_LEN..(i + 1) * OPEN_PATH_SLOT_LEN];
            match slot.iter().position(|&b| b == 0) {
                Some(0) => UNREAD_COMPONENT.to_string(),
                Some(end) if end < OPEN_PATH_SLOT_LEN - 1 => {
                    String::from_utf8_lossy(&slot[..end]).into_owned()
                }
                end => {
                    let end = end.unwrap_or(slot.len()).min(OPEN_PATH_SLOT_LEN - 1);
                    format!("{}{CUT_MARK}", String::from_utf8_lossy(&slot[..end]))
                }
            }
        })
        .collect()
}

/// Mount-relative path (`/a/b/c`) of a record.
pub fn relative_path(r: &OpenRecordRaw) -> String {
    let c = components(r);
    let parts: Vec<&str> = c
        .iter()
        .rev()
        .map(String::as_str)
        .filter(|s| *s != "/")
        .collect();
    format!("/{}", parts.join("/"))
}

fn comm_of(r: &OpenRecordRaw) -> String {
    let end = r.comm.iter().position(|&b| b == 0).unwrap_or(r.comm.len());
    String::from_utf8_lossy(&r.comm[..end]).into_owned()
}

/// Q8 (decided 2026-10-12): the uid that owns the credential file a record
/// opened, read by path. Only when the path still names the opened inode:
/// a replaced or vanished file yields `None`, and the rule only reports.
fn owner_of(path: &str, opened: InodeKey) -> Option<u32> {
    let meta = std::fs::metadata(path).ok()?;
    let found = InodeKey {
        dev: stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    };
    (found == opened).then(|| meta.uid())
}

/// Q8: whether the reader reads every file as root does — it holds
/// `CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH` in the initial user
/// namespace. A capability held only inside a user namespace
/// (`unshare -r`, a rootless container) grants nothing on the host's
/// files and does not count. Read when the record is drained: a reader
/// that has already exited counts as not capable.
fn reader_dac_capable(pid: u32) -> bool {
    const DAC_CAPS: u64 = (1 << 1) | (1 << 2); // CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    let caps = crate::response::caps_preflight::parse_cap_eff(&status).unwrap_or(0);
    if caps & DAC_CAPS == 0 {
        return false;
    }
    match (
        std::fs::read_link(format!("/proc/{pid}/ns/user")),
        std::fs::read_link("/proc/1/ns/user"),
    ) {
        (Ok(reader), Ok(init)) => reader == init,
        _ => false,
    }
}

/// Review 86: the capability a `FILE_CAP` record carries (see
/// [`open_reason::FILE_CAP`]): `VFS_CAP_FLAGS_EFFECTIVE` is bit 0 of
/// `magic_etc`, and revision 3 (`0x03`) in its top byte is a namespaced
/// capability.
fn file_capability(r: &OpenRecordRaw) -> FileCapability {
    FileCapability {
        permitted: u64::from(r.count) | (u64::from(r.flags) << 32),
        effective: r.mode & 1 != 0,
        namespaced: r.mode >> 24 == 3,
    }
}

/// External audit SNS-005: the path of a record whose filesystem root no
/// mount of the agent's namespace shows (a rootless container's overlay, a
/// filesystem mounted only in another namespace): relative to that root,
/// so never written as an absolute path. `mnt[<major>:<minor>:<root
/// inode>]` names the root as `/proc/<pid>/mountinfo` would.
fn unplaced_path(r: &OpenRecordRaw, rel: &str) -> String {
    let (major, minor) = (r.root_dev >> 20, r.root_dev & 0xF_FFFF);
    format!("mnt[{major}:{minor}:{}]{rel}", r.root_ino)
}

/// The events one record stands for.
pub fn events_of(r: &OpenRecordRaw, mounts: &mut MountTable) -> Vec<Event> {
    // Lab PR 225: a signal to a security tool's process carries no path.
    if r.reason & open_reason::DEFENDER_SIGNAL != 0 {
        return vec![Event::DefenderSignal {
            pid: r.pid,
            uid: r.uid,
            comm: comm_of(r),
            target_pid: r.flags,
            signal: r.count,
            timestamp_ns: r.timestamp_ns,
        }];
    }
    let rel = relative_path(r);
    let filename = match mounts.absolute((r.root_dev, r.root_ino), &rel) {
        Some(abs) => abs,
        None if r.path_truncated != 0 => format!("{CUT_MARK}{rel}"),
        None => unplaced_path(r, &rel),
    };
    let comm = comm_of(r);
    let mut out = Vec::new();
    let file_open =
        open_reason::SENSITIVE | open_reason::CRITICAL | open_reason::PERSIST | open_reason::PROBE;
    if r.reason & file_open != 0 {
        out.push(Event::FileOpen {
            pid: r.pid,
            uid: r.uid,
            gid: r.gid,
            comm: comm.clone(),
            filename: filename.clone(),
            flags: r.flags,
            timestamp_ns: r.timestamp_ns,
            path_from_user: false,
            kernel_class: r.reason,
        });
    }
    if r.reason & open_reason::CRED != 0 {
        out.push(Event::Fim(FimEvent {
            timestamp_ns: r.timestamp_ns,
            path: filename.clone(),
            op: FimOp::Opened,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: r.pid,
            modifier_uid: r.uid,
            modifier_comm: comm.clone(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: true,
            owner_uid: owner_of(
                &filename,
                InodeKey {
                    dev: r.dev,
                    ino: r.ino,
                },
            ),
            reader_dac_capable: r.uid != 0 && reader_dac_capable(r.pid),
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        }));
    }
    if r.reason & open_reason::FILE_CAP != 0 {
        out.push(Event::Fim(FimEvent {
            timestamp_ns: r.timestamp_ns,
            path: filename.clone(),
            op: FimOp::CapabilitySet,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: r.pid,
            modifier_uid: r.uid,
            modifier_comm: comm.clone(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: Some(file_capability(r)),
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        }));
    }
    // External audit POS-002: one event per crossing; an open crossing
    // both thresholds is one event, an overwrite one. EBPF-011: the cgroup
    // window's crossing is an overwrite crossing too, and says so.
    let overwrites = open_reason::MASS_OVERWRITE | open_reason::MASS_OVERWRITE_CGROUP;
    if r.reason & (open_reason::MASS_WRITE | overwrites) != 0 {
        out.push(Event::MassWrite {
            pid: r.pid,
            uid: r.uid,
            comm: comm.clone(),
            count: r.count,
            filename: filename.clone(),
            timestamp_ns: r.timestamp_ns,
            overwrites: r.reason & overwrites != 0,
            cgroup_window: r.reason & open_reason::MASS_OVERWRITE_CGROUP != 0,
        });
    }
    // Lab PR 225: the rename and unlink bursts (`inode_rename`,
    // `inode_unlink`), one record each, never combined with an open.
    if r.reason & open_reason::MASS_RENAME != 0 {
        out.push(Event::FileBurst {
            pid: r.pid,
            uid: r.uid,
            comm: comm.clone(),
            kind: nn_model::FileBurstKind::RenameExtension,
            count: r.count,
            appended: r.flags,
            sources: r.mode,
            filename: filename.clone(),
            timestamp_ns: r.timestamp_ns,
        });
    }
    if r.reason & open_reason::MASS_UNLINK != 0 {
        out.push(Event::FileBurst {
            pid: r.pid,
            uid: r.uid,
            comm,
            kind: nn_model::FileBurstKind::Unlink,
            count: r.count,
            appended: 0,
            sources: 0,
            filename,
            timestamp_ns: r.timestamp_ns,
        });
    }
    out
}

/// Ring label of the open-sensor pump (rejected-record counts, pump
/// liveness).
pub const PUMP_LABEL: &str = "open_sensor";

/// External audit SNS-008: one ring read, decoded. A record shorter than
/// [`OpenRecordRaw`] is not decoded; its length is kept in `rejected` so the
/// pump counts and reports it.
#[derive(Default)]
pub(crate) struct BatchDecoder {
    pub(crate) records: Vec<OpenRecordRaw>,
    pub(crate) rejected: Vec<usize>,
}

impl BatchDecoder {
    pub(crate) fn push(&mut self, item: &[u8]) {
        let size = std::mem::size_of::<OpenRecordRaw>();
        if item.len() < size {
            self.rejected.push(item.len());
        } else {
            self.records
                .push(bytemuck::pod_read_unaligned::<OpenRecordRaw>(&item[..size]));
        }
    }
}

/// [`BatchDecoder`] over a whole batch: `(records, rejected lengths)`.
#[cfg(test)]
pub(crate) fn decode_batch<'a>(
    items: impl IntoIterator<Item = &'a [u8]>,
) -> (Vec<OpenRecordRaw>, Vec<usize>) {
    let mut d = BatchDecoder::default();
    for item in items {
        d.push(item);
    }
    (d.records, d.rejected)
}

/// Drain the ring onto the agent's event bus until the receiver goes
/// away.
pub async fn pump(ring: RingBuf<MapData>, tx: crate::sensors::bus::BusSender) {
    let mut fd = match crate::async_fd::register(ring) {
        Ok(fd) => fd,
        Err(e) => {
            warn!(error = %e, "open sensor: cannot poll its ring — no file-open events");
            return;
        }
    };
    let mut mounts = MountTable::load();
    let size = std::mem::size_of::<OpenRecordRaw>();
    let mut reject = RejectThrottle::new();
    loop {
        let mut guard = match fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "open sensor: ring wait failed");
                return;
            }
        };
        let mut batch = BatchDecoder::default();
        {
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                batch.push(&item);
            }
        }
        guard.clear_ready();
        // External audit SNS-008: a short record is counted and WARNed
        // (coalesced), like every other pump's, not skipped at debug level.
        for got in &batch.rejected {
            reject.record(PUMP_LABEL, size, *got);
        }
        if batch.rejected.is_empty() {
            reject.flush_idle(PUMP_LABEL, size);
        }
        for r in send_order(&batch.records) {
            for ev in events_of(r, &mut mounts) {
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// The order a batch's records are sent in (review #471 M2): the signals
/// to a security tool (P0, tamper) first, then the file records in the
/// ring's order. A file record other than an open waits for room on a full
/// P2 (review 75), and the pump with it: a signal read in the same batch
/// behind it does not wait too. (One read in a later batch still can, while
/// P2 is full of file events other than opens: `EVENT_BUS.md`, Open.)
pub(crate) fn send_order(records: &[OpenRecordRaw]) -> impl Iterator<Item = &OpenRecordRaw> {
    let signal = |r: &&OpenRecordRaw| r.reason & open_reason::DEFENDER_SIGNAL != 0;
    records
        .iter()
        .filter(signal)
        .chain(records.iter().filter(move |r| !signal(r)))
}

/// External audit EBPF-011: the kernel's count of classifications whose
/// walk stopped at the depth cap (`OPEN_DEPTH_CAPPED`), read at every rule
/// refresh and logged at most once per [`DEPTH_CAP_LOG_EVERY`] with the
/// number since the last line.
#[derive(Debug, Default)]
pub struct DepthCapLog {
    seen: u64,
    logged: u64,
    last: Option<Instant>,
}

pub const DEPTH_CAP_LOG_EVERY: Duration = Duration::from_secs(600);

impl DepthCapLog {
    /// The kernel's running `total` at `now`: the count to log since the
    /// last line, when one is due.
    pub fn note(&mut self, total: u64, now: Instant) -> Option<u64> {
        self.seen = self.seen.max(total);
        let new = self.seen - self.logged;
        if new == 0
            || self
                .last
                .is_some_and(|t| now.duration_since(t) < DEPTH_CAP_LOG_EVERY)
        {
            return None;
        }
        self.logged = self.seen;
        self.last = Some(now);
        Some(new)
    }

    /// Read the counter from `maps` and log what is due.
    pub fn sample(&mut self, maps: &OpenSensorMaps) {
        let Ok(total) = maps.depth_capped_total() else {
            return;
        };
        if let Some(n) = self.note(total, Instant::now()) {
            info!(
                depth = OPEN_CLASSIFY_DEPTH,
                directories = n,
                "file-open sensor: directories classified without reaching their filesystem root \
                 (ancestor walk capped) — a rule further up was not applied to them"
            );
        }
    }
}

/// Rebuild the rules from the host (new homes, runtime directories, paths
/// created since) and write the difference against what the maps hold
/// (`current`); `None` when nothing changed. The caller keeps
/// [`Applied::in_maps`] as the next `current`.
pub fn refresh(
    maps: &mut OpenSensorMaps,
    current: &RuleSet,
    carveout_extras: &[String],
) -> Option<Applied> {
    let next = RuleSet::build(&RuleInputs::from_host(carveout_extras));
    if next == *current {
        return None;
    }
    warn_refused_carveouts(Some(current), &next);
    let applied = maps.apply(&next, Some(current));
    info!(
        inodes = next.inodes.len(),
        children = next.children.len(),
        runtime_dirs = next.runtime.len(),
        failed = applied.failed,
        "open sensor: rules refreshed"
    );
    Some(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit SNS-008: a short record is not decoded and its length
    /// is reported, so the pump counts it (it was a `debug!` and gone).
    #[test]
    fn decode_batch_reports_short_records() {
        let mut rec: OpenRecordRaw = bytemuck::Zeroable::zeroed();
        rec.pid = 4242;
        let full = bytemuck::bytes_of(&rec).to_vec();
        let mut longer = full.clone();
        longer.extend_from_slice(&[0u8; 8]);
        let short = vec![0u8; 16];
        let empty: Vec<u8> = Vec::new();
        let (records, rejected) = decode_batch([
            full.as_slice(),
            short.as_slice(),
            longer.as_slice(),
            empty.as_slice(),
        ]);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.pid == 4242));
        assert_eq!(rejected, vec![16, 0]);
    }

    /// External audit SNS-010: uid 0's declared home and the service
    /// accounts' own homes are home trees; shared system directories and
    /// the overflow accounts are not.
    #[test]
    fn home_roots_read_every_account_s_own_home() {
        let passwd = "root:x:0:0:root:/srv/root-home:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
                      mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
                      rtkit:x:107:113::/proc:/usr/sbin/nologin\n\
                      tss:x:59:59::/dev/null:/sbin/nologin\n\
                      sshd:x:74:74::/var/empty/sshd:/sbin/nologin\n\
                      unbound:x:995:993::/etc/unbound:/sbin/nologin\n\
                      dnsmasq:x:116:65534::/var/lib/misc:/usr/sbin/nologin\n\
                      postgres:x:113:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n\
                      jenkins:x:114:121::/var/lib/jenkins:/bin/bash\n\
                      alice:x:1000:1000::/home/alice:/bin/bash\n\
                      bob:x:1001:1001::/srv/bob/:/bin/sh\n\
                      carol:x:200000:200000::/home/carol:/bin/bash\n\
                      twin:x:1002:1002::/home/alice:/bin/bash\n\
                      rel:x:1003:1003::home/rel:/bin/bash\n\
                      nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
                      nobody:x:99:99:Nobody:/srv/nobody:/sbin/nologin\n\
                      nfsnobody:x:4294967294:4294967294::/var/lib/nfs:/sbin/nologin\n\
                      broken line\n";
        assert_eq!(
            home_roots(passwd),
            vec![
                PathBuf::from("/root"),
                PathBuf::from("/srv/root-home"),
                PathBuf::from("/var/lib/postgresql"),
                PathBuf::from("/var/lib/jenkins"),
                PathBuf::from("/home/alice"),
                PathBuf::from("/srv/bob"),
                PathBuf::from("/home/carol"),
            ]
        );
        for shared in [
            "/",
            "//var/lib",
            "/var/lib/",
            "/usr/sbin",
            "/etc/x",
            "/dev/null",
        ] {
            assert!(is_shared_system_dir(Path::new(shared)), "{shared}");
        }
        for own in [
            "/var/lib/postgresql",
            "/home/alice",
            "/srv/bob",
            "/etcetera",
        ] {
            assert!(!is_shared_system_dir(Path::new(own)), "{own}");
        }
    }

    /// External audit SNS-010: a declared home becomes a home tree only
    /// where it resolves to an existing directory that is not a shared
    /// system one (a symbolic link to `/etc` is not a home).
    #[test]
    fn a_home_is_a_tree_where_it_resolves_to_an_account_s_own_directory() {
        let t = tempfile::tempdir().unwrap();
        let own = t.path().join("svc");
        std::fs::create_dir(&own).unwrap();
        let to_etc = t.path().join("to-etc");
        std::os::unix::fs::symlink("/etc", &to_etc).unwrap();
        let to_own = t.path().join("to-svc");
        std::os::unix::fs::symlink(&own, &to_own).unwrap();
        let file = t.path().join("file");
        std::fs::write(&file, "").unwrap();
        let set = RuleSet::build(&RuleInputs {
            homes: vec![own.clone(), to_etc, to_own, file, t.path().join("missing")],
            probe_dir: t.path().join("probe"),
            ..RuleInputs::default()
        });
        let homes: Vec<&InodeKey> = set
            .inodes
            .iter()
            .filter(|(_, b)| **b & TREE_HOME != 0)
            .map(|(k, _)| k)
            .collect();
        assert_eq!(homes, vec![&key_of(&std::fs::metadata(&own).unwrap())]);
    }

    /// Lab PR 175: an unplaced path names its filesystem as mountinfo does.
    #[test]
    fn an_unplaced_path_names_its_filesystem() {
        use crate::path_text::unplaced_root_dev;
        let r = record(
            open_reason::MASS_WRITE,
            &["x", "lib", "/"],
            ((7 << 20) | 77, 2),
        );
        let path = unplaced_path(&r, &relative_path(&r));
        assert_eq!(path, "mnt[7:77:2]/lib/x");
        assert_eq!(unplaced_root_dev(&path), Some((7, 77)));
        for other in ["/home/u/x", "…/lib/x", "mnt[7:77]/x", "mnt[a:77:2]/x"] {
            assert_eq!(unplaced_root_dev(other), None, "{other}");
        }
    }

    #[test]
    fn mount_points_decode_octal_escapes() {
        let mi = "22 1 253:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n\
                  40 22 0:45 / /mnt/with\\040space rw - tmpfs tmpfs rw\n";
        assert_eq!(
            mount_points(mi),
            vec!["/".to_string(), "/mnt/with space".to_string()]
        );
    }

    /// A `mountinfo` fixture with one mount at `mp`, and the root key a
    /// `stat()` of `mp` gives.
    fn one_mount(info: &Path, mp: &Path) {
        std::fs::write(
            info,
            format!("40 22 0:45 / {} rw - tmpfs tmpfs rw\n", mp.display()),
        )
        .unwrap();
    }

    fn root_of(p: &Path) -> (u64, u64) {
        let k = key_of(&std::fs::metadata(p).unwrap());
        (k.dev, k.ino)
    }

    /// External audit SNS-004: a hit was never checked again — a
    /// filesystem root that moved to another mount point (an anonymous
    /// device reused by the next tmpfs) kept its old mount point. The
    /// table is re-read once it is older than the TTL, hit or not.
    #[test]
    fn stale_hit_is_refreshed_after_ttl() {
        let t = tempfile::tempdir().unwrap();
        let (a, b, info) = (t.path().join("a"), t.path().join("b"), t.path().join("mi"));
        std::fs::create_dir(&a).unwrap();
        one_mount(&info, &a);
        let mut mounts = MountTable::load_from(&info);
        let root = root_of(&a);
        let under = |p: &Path| Some(format!("{}/f", p.display()));
        assert_eq!(mounts.absolute(root, "/f"), under(&a));
        // the same root (dev, inode) now at another mount point
        std::fs::rename(&a, &b).unwrap();
        one_mount(&info, &b);
        // a fixture file never polls a change: inside the TTL the table
        // answers as read
        assert_eq!(mounts.absolute(root, "/f"), under(&a));
        mounts.loaded = Instant::now().checked_sub(MOUNT_HIT_TTL);
        assert_eq!(mounts.absolute(root, "/f"), under(&b));
    }

    /// External audit SNS-004: after a polled change, while the re-read
    /// waits for the throttle, a hit whose mount point no longer shows its
    /// root is dropped (unplaced), never answered with that mount point.
    #[test]
    fn a_changed_table_never_answers_with_a_mount_point_that_lost_its_root() {
        let t = tempfile::tempdir().unwrap();
        let (a, b, info) = (t.path().join("a"), t.path().join("b"), t.path().join("mi"));
        std::fs::create_dir(&a).unwrap();
        one_mount(&info, &a);
        let mut mounts = MountTable::load_from(&info);
        let root = root_of(&a);
        // a change polled, the mount point still shows the root: answered
        mounts.changed = true;
        assert_eq!(
            mounts.absolute(root, "/f"),
            Some(format!("{}/f", a.display()))
        );
        std::fs::rename(&a, &b).unwrap();
        one_mount(&info, &b);
        assert_eq!(mounts.absolute(root, "/f"), None);
        let r = record(open_reason::PERSIST, &["f", "/"], root);
        let Event::FileOpen { filename, .. } = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert!(filename.starts_with("mnt["), "{filename}");
        // the throttle passed: the re-read table places it again
        mounts.loaded = Instant::now().checked_sub(MOUNT_REFRESH_MIN);
        assert_eq!(
            mounts.absolute(root, "/f"),
            Some(format!("{}/f", b.display()))
        );
        assert!(!mounts.changed);
    }

    /// External audit SNS-004: a change of the mount table is polled on
    /// the open `mountinfo` without waiting; a regular file never reports
    /// one.
    #[test]
    fn a_regular_file_never_polls_a_mount_change() {
        let t = tempfile::tempdir().unwrap();
        let info = t.path().join("mi");
        std::fs::write(&info, "").unwrap();
        let f = std::fs::File::open(&info).unwrap();
        assert!(!mounts_changed(&f));
        assert!(MountTable::load_from(&info).watch.is_some());
        assert!(MountTable::load_from(&t.path().join("none"))
            .watch
            .is_none());
    }

    /// A generation slot that can fail its read.
    #[derive(Default)]
    struct StubSlot {
        value: u32,
        fail_read: bool,
        writes: Vec<u32>,
    }

    impl GenerationSlot for StubSlot {
        fn read_generation(&self) -> Result<u32> {
            if self.fail_read {
                return Err(anyhow!("EFAULT: lookup failed"));
            }
            Ok(self.value)
        }
        fn write_generation(&mut self, value: u32) -> Result<()> {
            self.value = value;
            self.writes.push(value);
            Ok(())
        }
    }

    /// External audit SNS-011: a failed read took the generation to 1 (read
    /// as 0, plus one), back to a value classes may still be cached under.
    /// It is an error now, nothing is written, and the rule write reports
    /// the generation as not bumped (degraded).
    #[test]
    fn bump_generation_propagates_read_error() {
        let mut slot = StubSlot {
            value: 7,
            fail_read: true,
            ..StubSlot::default()
        };
        let mut last = 5;
        let e = bump_generation_in(&mut slot, &mut last).unwrap_err();
        assert!(format!("{e:#}").contains("DIR_CLASS_GEN"), "{e:#}");
        assert!(slot.writes.is_empty());
        assert_eq!((slot.value, last), (7, 5));
        let mut maps = FakeMaps {
            cap: 8,
            ..FakeMaps::default()
        };
        maps.slot.fail_read = true;
        let a = apply_rules(&mut maps, &busy_set(), None);
        assert!(a.generation_failed && a.degraded());
        assert!(a
            .first_error
            .as_deref()
            .is_some_and(|e| e.contains("DIR_CLASS_GEN")));
    }

    /// External audit SNS-011: the generation moves forward from the later
    /// of the slot and this process's last write, in serial order, and is
    /// never 0.
    #[test]
    fn generation_never_moves_back() {
        let mut slot = StubSlot::default();
        let mut last = 0;
        bump_generation_in(&mut slot, &mut last).unwrap();
        assert_eq!(slot.value, 1);
        slot.value = 41; // kernel bumps (directory renames)
        bump_generation_in(&mut slot, &mut last).unwrap();
        assert_eq!((slot.value, last), (42, 42));
        slot.value = 0; // reset behind this process's back
        bump_generation_in(&mut slot, &mut last).unwrap();
        assert_eq!(slot.value, 43, "not back to 1");
        slot.value = 100; // the kernel is ahead
        bump_generation_in(&mut slot, &mut last).unwrap();
        assert_eq!(slot.value, 101);
        // the wrap skips 0, and the kernel's small values after it are
        // still later than this process's last write
        assert_eq!(next_generation(u32::MAX, u32::MAX - 1), 1);
        assert_eq!(next_generation(5, u32::MAX), 6);
        assert_eq!(next_generation(u32::MAX - 3, 2), 3);
        assert_eq!(next_generation(0, 0), 1);
    }

    #[test]
    fn path_rules_register_files_directories_and_missing_children() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::create_dir_all(root.join("etc/cron.d")).unwrap();
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::write(root.join("etc/crontab"), "").unwrap();
        let p = |s: &str| root.join(s).display().to_string();
        let inputs = RuleInputs {
            critical: vec![p("etc/crontab"), format!("{}/", p("root/.ssh"))],
            persistence: vec![format!("{}/", p("etc/cron.d")), p("etc/.bashrc")],
            probe_dir: root.join("run/probe"),
            ..RuleInputs::default()
        };
        let set = RuleSet::build(&inputs);
        let key = |s: &str| key_of(&std::fs::metadata(root.join(s)).unwrap());
        assert_eq!(set.inodes.get(&key("etc/crontab")), Some(&FILE_CRITICAL));
        // its directory is marked, so the kernel looks the file up there
        assert_eq!(
            set.inodes.get(&key("etc")).map(|b| b & DIR_HAS_FILES),
            Some(DIR_HAS_FILES)
        );
        assert_eq!(set.inodes.get(&key("etc/cron.d")), Some(&TREE_PERSIST));
        // /etc/.bashrc is missing: a child rule on etc, and etc reads leaves.
        let bashrc = ChildRuleKey {
            parent: key("etc"),
            name: name32(".bashrc"),
        };
        assert_eq!(set.children.get(&bashrc), Some(&FILE_PERSIST));
        assert_eq!(
            set.inodes.get(&key("etc")).map(|b| b & CHILD_FILES),
            Some(CHILD_FILES)
        );
        // root/.ssh/ is missing two levels down: the first missing name
        // under the temp dir carries the tree bits.
        let ssh = ChildRuleKey {
            parent: key_of(&std::fs::metadata(root).unwrap()),
            name: name32("root"),
        };
        assert_eq!(set.children.get(&ssh), Some(&TREE_CRITICAL));
        // the probe directory is missing under an existing run/: a child
        // rule for its children
        let probe = ChildRuleKey {
            parent: key("run"),
            name: name32("probe"),
        };
        assert_eq!(set.children.get(&probe), Some(&CHILDREN_PROBE));
        assert!(set.skipped.is_empty(), "{:?}", set.skipped);
        // two missing levels: only subtree bits survive, a children-only
        // rule is skipped
        let deep = RuleSet::build(&RuleInputs {
            probe_dir: root.join("none/probe"),
            ..RuleInputs::default()
        });
        assert!(deep.children.is_empty());
        assert_eq!(deep.skipped.len(), 1);
    }

    #[test]
    fn carveouts_are_trees_with_or_without_the_final_slash() {
        let t = tempfile::tempdir().unwrap();
        // canonical: a carve-out never follows a link (POS-010)
        let root = &std::fs::canonicalize(t.path()).unwrap();
        std::fs::create_dir_all(root.join("state/tool")).unwrap();
        std::fs::write(root.join("state/app.log"), "").unwrap();
        let p = |s: &str| root.join(s).display().to_string();
        let set = RuleSet::build(&RuleInputs {
            carveout: vec![p("state/tool"), p("later"), p("state/app.log")],
            probe_dir: root.join("probe"),
            ..RuleInputs::default()
        });
        let key = |s: &str| key_of(&std::fs::metadata(root.join(s)).unwrap());
        assert_eq!(set.inodes.get(&key("state/tool")), Some(&TREE_CARVEOUT));
        // missing: caught as a directory when it appears
        let later = ChildRuleKey {
            parent: key_of(&std::fs::metadata(root).unwrap()),
            name: name32("later"),
        };
        assert_eq!(set.children.get(&later), Some(&TREE_CARVEOUT));
        // a carve-out naming a file cannot be a directory class
        assert_eq!(set.skipped, vec![p("state/app.log")]);
        assert!(set.refused.is_empty(), "{:?}", set.refused);
    }

    /// External audit POS-010 (lab PR 198): a user who replaces the
    /// directory of a signed carve-out (`~/.claude/`) with a link to
    /// their home or `/` moved the carve-out to that tree at the
    /// next refresh (`metadata` follows links). A link anywhere on the path
    /// now refuses it, and the tree it points to gets no carve-out.
    #[test]
    fn a_carveout_never_follows_a_symlink() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        std::fs::create_dir_all(root.join("home/u/Documents")).unwrap();
        std::fs::create_dir_all(root.join("home/u/real-tool")).unwrap();
        // `~/.claude` → `~`; `~/via` → `~/Documents`, a carve-out below it;
        // `~/dangling` → a name that does not exist yet.
        std::os::unix::fs::symlink(root.join("home/u"), root.join("home/u/.claude")).unwrap();
        std::os::unix::fs::symlink(root.join("home/u/Documents"), root.join("home/u/via")).unwrap();
        std::os::unix::fs::symlink(root.join("home/u/later"), root.join("home/u/dangling"))
            .unwrap();
        let p = |s: &str| root.join(s).display().to_string();
        let set = RuleSet::build(&RuleInputs {
            carveout: vec![
                format!("{}/", p("home/u/.claude")),
                p("home/u/via/sub"),
                p("home/u/dangling"),
                p("home/u/real-tool"),
            ],
            probe_dir: root.join("probe"),
            ..RuleInputs::default()
        });
        let key = |s: &str| key_of(&std::fs::metadata(root.join(s)).unwrap());
        assert_eq!(
            set.inodes.get(&key("home/u")),
            None,
            "the home got a carve-out"
        );
        assert_eq!(set.inodes.get(&key("home/u/Documents")), None);
        assert_eq!(
            set.inodes.get(&key("home/u/real-tool")),
            Some(&TREE_CARVEOUT)
        );
        assert!(
            set.children.values().all(|b| b & TREE_CARVEOUT == 0),
            "{:?}",
            set.children
        );
        assert_eq!(set.refused.len(), 3, "{:?}", set.refused);
        for (r, link) in set
            .refused
            .iter()
            .zip(["home/u/.claude", "home/u/via", "home/u/dangling"])
        {
            assert!(r.contains(&format!("`{}`", p(link))), "{r}");
        }
        assert!(set.skipped.is_empty(), "{:?}", set.skipped);
    }

    #[test]
    fn cred_names_cut_like_the_kernel() {
        let k = name_key("application_default_credentials.json", "gcloud");
        assert_eq!(&k[..31], b"application_default_credentials");
        assert_eq!(k[31], 0);
        assert_eq!(&k[32..38], b"gcloud");
    }

    fn record(reason: u32, comps: &[&str], root: (u64, u64)) -> OpenRecordRaw {
        let mut r: OpenRecordRaw = bytemuck::Zeroable::zeroed();
        r.reason = reason;
        r.pid = 42;
        r.uid = 1000;
        r.flags = 1;
        r.count = 20;
        r.comm[..3].copy_from_slice(b"cat");
        for (i, c) in comps.iter().enumerate() {
            r.path[i * OPEN_PATH_SLOT_LEN..i * OPEN_PATH_SLOT_LEN + c.len()]
                .copy_from_slice(c.as_bytes());
        }
        r.path_n = comps.len() as u16;
        (r.root_dev, r.root_ino) = root;
        r
    }

    /// Lab PR 225: the rename and unlink bursts and the signal to a
    /// security tool, as the kernel reports them.
    #[test]
    fn burst_and_defender_records_become_their_events() {
        let mut mounts = MountTable::default();
        mounts.roots.insert((7, 2), "/".into());
        mounts.loaded = Some(Instant::now());
        let mut r = record(
            open_reason::MASS_RENAME,
            &["f020.locked", "nn-malsim", "srv", "/"],
            (7, 2),
        );
        r.flags = 18;
        r.mode = 4;
        let ev = events_of(&r, &mut mounts);
        assert!(
            matches!(&ev[..], [Event::FileBurst {
                kind: nn_model::FileBurstKind::RenameExtension,
                count: 20,
                appended: 18,
                sources: 4,
                filename,
                ..
            }] if filename == "/srv/nn-malsim/f020.locked"),
            "{ev:?}"
        );
        let r = record(
            open_reason::MASS_UNLINK,
            &["f020", "nn-malsim", "srv", "/"],
            (7, 2),
        );
        assert!(matches!(
            &events_of(&r, &mut mounts)[..],
            [Event::FileBurst {
                kind: nn_model::FileBurstKind::Unlink,
                count: 20,
                ..
            }]
        ));
        let mut r = record(open_reason::DEFENDER_SIGNAL, &[], (0, 0));
        r.count = 9;
        r.flags = 777;
        assert!(matches!(
            &events_of(&r, &mut mounts)[..],
            [Event::DefenderSignal {
                pid: 42,
                target_pid: 777,
                signal: 9,
                ..
            }]
        ));
    }

    /// Review #471 M2: a batch's signals to a security tool are sent
    /// first, the file records after them in the ring's order.
    #[test]
    fn a_batch_sends_its_defender_signals_first() {
        let mut batch = Vec::new();
        for (i, reason) in [
            open_reason::CRED,
            open_reason::MASS_WRITE,
            open_reason::DEFENDER_SIGNAL,
            open_reason::SENSITIVE,
            open_reason::DEFENDER_SIGNAL,
        ]
        .into_iter()
        .enumerate()
        {
            let mut r = record(reason, &[], (0, 0));
            r.pid = i as u32;
            batch.push(r);
        }
        let order: Vec<u32> = send_order(&batch).map(|r| r.pid).collect();
        assert_eq!(order, [2, 4, 0, 1, 3]);
    }

    #[test]
    fn records_become_the_events_consumers_read() {
        let mut mounts = MountTable::default();
        mounts.roots.insert((7, 2), "/".into());
        mounts.roots.insert((9, 1), "/run".into());
        mounts.loaded = Some(Instant::now());
        let r = record(
            open_reason::PERSIST | open_reason::MASS_WRITE,
            &["x.service", "system", "systemd", "etc", "/"],
            (7, 2),
        );
        let ev = events_of(&r, &mut mounts);
        assert!(
            matches!(&ev[0], Event::FileOpen { filename, flags: 1, .. } if filename == "/etc/systemd/system/x.service")
        );
        assert!(
            matches!(&ev[1], Event::MassWrite { count: 20, filename, overwrites: false, .. } if filename == "/etc/systemd/system/x.service")
        );
        // External audit POS-002: the overwrite threshold, alone or with
        // the write one on the same open, is one event that says so.
        for reason in [
            open_reason::MASS_OVERWRITE,
            open_reason::MASS_WRITE | open_reason::MASS_OVERWRITE,
        ] {
            let r = record(reason, &["a.docx", "nn", "home", "/"], (7, 2));
            let ev = events_of(&r, &mut mounts);
            assert_eq!(ev.len(), 1);
            assert!(
                matches!(&ev[0], Event::MassWrite { overwrites: true, filename, .. } if filename == "/home/nn/a.docx")
            );
        }
        let r = record(
            open_reason::PROBE,
            &["n0nce", "probe", "northnarrow", "/"],
            (9, 1),
        );
        assert!(
            matches!(&events_of(&r, &mut mounts)[0], Event::FileOpen { filename, .. } if filename == "/run/northnarrow/probe/n0nce")
        );
        let r = record(
            open_reason::CRED,
            &["credentials", ".aws", "alice", "home", "/"],
            (7, 2),
        );
        assert!(
            matches!(&events_of(&r, &mut mounts)[0], Event::Fim(fe) if fe.op == FimOp::Opened && fe.path == "/home/alice/.aws/credentials" && fe.modifier_comm == "cat")
        );
        // An unknown root keeps the mount-relative path, marked (SNS-005).
        let r = record(open_reason::CRED, &["credentials", ".aws", "/"], (5, 5));
        assert!(
            matches!(&events_of(&r, &mut mounts)[0], Event::Fim(fe) if fe.path == "mnt[0:5:5]/.aws/credentials")
        );
    }

    /// External audit SNS-005: a record whose filesystem root no mount of
    /// the agent's namespace shows (a rootless container's overlay) never
    /// reads as a host path; the kernel's class travels with the event.
    #[test]
    fn unresolved_root_is_marked() {
        let mut mounts = MountTable {
            loaded: Some(Instant::now()),
            ..MountTable::default()
        };
        let dev = (0x2d << 20) | 7; // 45:7
        let r = record(
            open_reason::PERSIST,
            &["job", "cron.d", "etc", "/"],
            (dev, 256),
        );
        let ev = events_of(&r, &mut mounts);
        let Event::FileOpen {
            filename,
            kernel_class,
            ..
        } = &ev[0]
        else {
            panic!("{ev:?}")
        };
        assert_eq!(filename, "mnt[45:7:256]/etc/cron.d/job");
        assert_eq!(*kernel_class, open_reason::PERSIST);
        assert!(!path_is_exact(filename));
        let r = record(
            open_reason::CRED,
            &["credentials", ".aws", "root", "/"],
            (dev, 256),
        );
        let Event::Fim(fe) = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(fe.path, "mnt[45:7:256]/root/.aws/credentials");
        // the credential rules match by fragment and still see it
        assert!(fe.path.contains("/.aws/credentials"));
        assert_eq!(fe.owner_uid, None);
        // a walk that never reached a root keeps its own mark
        let mut r = record(open_reason::PERSIST, &["job", "cron.d"], (0, 0));
        r.path_truncated = 1;
        let Event::FileOpen { filename, .. } = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(filename, "…/cron.d/job");
        // a placed path is exact
        mounts.roots.insert((dev, 256), "/".into());
        let r = record(
            open_reason::PERSIST,
            &["job", "cron.d", "etc", "/"],
            (dev, 256),
        );
        let Event::FileOpen { filename, .. } = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(filename, "/etc/cron.d/job");
        assert!(path_is_exact(filename));
    }

    /// External audit SNS-006: a 31-byte component may be a longer name the
    /// kernel cut; it is marked and the path is not exact.
    #[test]
    fn long_component_is_marked() {
        let mut mounts = MountTable::default();
        mounts.roots.insert((7, 2), "/".into());
        mounts.loaded = Some(Instant::now());
        let long = "a-project-with-a-very-long-name"; // 31 bytes
        assert_eq!(long.len(), OPEN_PATH_SLOT_LEN - 1);
        let r = record(
            open_reason::CRED,
            &["credentials", ".aws", long, "home", "/"],
            (7, 2),
        );
        let Event::Fim(fe) = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(fe.path, format!("/home/{long}…/.aws/credentials"));
        assert!(!path_is_exact(&fe.path));
        // a slot with no NUL at all (never written by the kernel) is cut too
        let mut r = record(open_reason::PERSIST, &["x", "etc", "/"], (7, 2));
        r.path[..OPEN_PATH_SLOT_LEN].fill(b'b');
        let Event::FileOpen { filename, .. } = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(
            filename,
            &format!("/etc/{}…", "b".repeat(OPEN_PATH_SLOT_LEN - 1))
        );
        // 30 bytes fit whole
        let r = record(open_reason::PERSIST, &[&long[..30], "etc", "/"], (7, 2));
        let Event::FileOpen { filename, .. } = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(filename, &format!("/etc/{}", &long[..30]));
        assert!(path_is_exact(filename));
    }

    /// External audit SNS-006: a component the kernel could not read (an
    /// empty slot) is `?`, not an empty name that turns into `//`.
    #[test]
    fn failed_component_read_is_marked() {
        let mut mounts = MountTable::default();
        mounts.roots.insert((7, 2), "/".into());
        mounts.loaded = Some(Instant::now());
        let r = record(
            open_reason::CRITICAL,
            &["sshd_config", "", "etc", "/"],
            (7, 2),
        );
        let Event::FileOpen { filename, .. } = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        assert_eq!(filename, "/etc/?/sshd_config");
        assert!(!path_is_exact(filename));
    }

    /// External audit EBPF-011: the cgroup window's crossing is an
    /// overwrite mass write that names its window.
    #[test]
    fn cgroup_crossing_is_an_overwrite_mass_write() {
        let mut mounts = MountTable::default();
        mounts.roots.insert((7, 2), "/".into());
        mounts.loaded = Some(Instant::now());
        let mut r = record(
            open_reason::MASS_OVERWRITE_CGROUP,
            &["a.docx", "u", "home", "/"],
            (7, 2),
        );
        r.count = 40;
        let ev = events_of(&r, &mut mounts);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert!(matches!(
            &ev[0],
            Event::MassWrite {
                count: 40,
                overwrites: true,
                cgroup_window: true,
                ..
            }
        ));
        let r = record(
            open_reason::MASS_OVERWRITE,
            &["a.docx", "u", "home", "/"],
            (7, 2),
        );
        assert!(matches!(
            &events_of(&r, &mut mounts)[0],
            Event::MassWrite {
                overwrites: true,
                cgroup_window: false,
                ..
            }
        ));
    }

    /// External audit EBPF-011: the depth-cap count is logged when it
    /// grows, at most once per interval, with what accumulated meanwhile.
    #[test]
    fn depth_cap_count_is_logged_once_per_interval() {
        let mut log = DepthCapLog::default();
        let t0 = Instant::now();
        assert_eq!(log.note(0, t0), None);
        assert_eq!(log.note(3, t0), Some(3));
        assert_eq!(log.note(10, t0 + Duration::from_secs(60)), None);
        assert_eq!(log.note(12, t0 + DEPTH_CAP_LOG_EVERY), Some(9));
        assert_eq!(log.note(12, t0 + 3 * DEPTH_CAP_LOG_EVERY), None);
    }

    /// Rule maps of fixed capacities, like the kernel's.
    #[derive(Default)]
    struct FakeMaps {
        cap: usize,
        inodes: HashMap<InodeKey, u32>,
        children: HashMap<ChildRuleKey, u32>,
        names: HashMap<[u8; 2 * OPEN_NAME_LEN], u32>,
        runtime: HashMap<InodeKey, u32>,
        /// Generation bumps that went through.
        generation: u32,
        /// External audit SNS-011: the slot behind them.
        slot: StubSlot,
        last: u32,
    }

    fn put<K: std::hash::Hash + Eq>(
        m: &mut HashMap<K, u32>,
        cap: usize,
        k: K,
        v: u32,
    ) -> Result<()> {
        if !m.contains_key(&k) && m.len() >= cap {
            return Err(anyhow!("E2BIG: map full"));
        }
        m.insert(k, v);
        Ok(())
    }

    impl RuleMaps for FakeMaps {
        fn insert_inode(&mut self, k: InodeKey, v: u32) -> Result<()> {
            put(&mut self.inodes, self.cap, k, v)
        }
        fn remove_inode(&mut self, k: InodeKey) -> Result<()> {
            self.inodes.remove(&k);
            Ok(())
        }
        fn insert_child(&mut self, k: ChildRuleKey, v: u32) -> Result<()> {
            put(&mut self.children, self.cap, k, v)
        }
        fn remove_child(&mut self, k: ChildRuleKey) -> Result<()> {
            self.children.remove(&k);
            Ok(())
        }
        fn insert_name(&mut self, k: [u8; 2 * OPEN_NAME_LEN], v: u32) -> Result<()> {
            put(&mut self.names, self.cap, k, v)
        }
        fn remove_name(&mut self, k: [u8; 2 * OPEN_NAME_LEN]) -> Result<()> {
            self.names.remove(&k);
            Ok(())
        }
        fn insert_runtime(&mut self, k: InodeKey, uid: u32) -> Result<()> {
            put(&mut self.runtime, self.cap, k, uid)
        }
        fn remove_runtime(&mut self, k: InodeKey) -> Result<()> {
            self.runtime.remove(&k);
            Ok(())
        }
        fn bump_generation(&mut self) -> Result<()> {
            bump_generation_in(&mut self.slot, &mut self.last)?;
            self.generation += 1;
            Ok(())
        }
    }

    fn ik(ino: u64) -> InodeKey {
        InodeKey { dev: 7, ino }
    }

    /// Two posture rules, one child and one name rule, two homes and two
    /// runtime directories.
    fn busy_set() -> RuleSet {
        let mut set = RuleSet::default();
        set.inodes.insert(ik(1), FILE_SENSITIVE);
        set.inodes.insert(ik(2), TREE_PERSIST | TREE_HOME);
        set.inodes.insert(ik(10), TREE_HOME);
        set.inodes.insert(ik(11), TREE_HOME);
        set.inodes.insert(ik(20), TREE_RUNTIME);
        set.inodes.insert(ik(21), TREE_RUNTIME);
        set.runtime.insert(ik(20), 1000);
        set.runtime.insert(ik(21), 1001);
        set.children.insert(
            ChildRuleKey {
                parent: ik(2),
                name: name32(".bashrc"),
            },
            FILE_PERSIST,
        );
        set.names.insert(name_key(".gnupg", ""), TREE_CRED);
        set
    }

    /// External audit SNS-007: a full map refused the first rule and the
    /// whole write stopped there — no other map written, no generation
    /// bump (stale cached classes), nothing to tell the caller what was in.
    #[test]
    fn apply_continues_and_bumps_generation_on_full_map() {
        let mut maps = FakeMaps {
            cap: 3,
            ..FakeMaps::default()
        };
        let set = busy_set();
        let a = apply_rules(&mut maps, &set, None);
        assert_eq!(
            maps.generation, 1,
            "the generation is bumped whatever failed"
        );
        assert_eq!(a.failed, 3);
        assert!(a.degraded());
        assert!(a
            .first_error
            .as_deref()
            .is_some_and(|e| e.contains("E2BIG")));
        // the other maps were written past the refused inode rules
        assert_eq!(maps.children.len(), 1);
        assert_eq!(maps.names.len(), 1);
        // the posture's rules went in first, then a home
        let mut held: Vec<u64> = maps.inodes.keys().map(|k| k.ino).collect();
        held.sort();
        assert_eq!(held, vec![1, 2, 10]);
        // what the caller keeps is what the maps hold; a runtime owner
        // only where its directory rule went in (none here)
        assert_eq!(a.in_maps.inodes, maps.inodes);
        assert!(a.in_maps.runtime.is_empty() && maps.runtime.is_empty());
        assert_eq!(a.inserted, 3 + 1 + 1);
        // the next refresh tries the refused rules again
        maps.cap = 8;
        let b = apply_rules(&mut maps, &set, Some(&a.in_maps));
        assert!(!b.degraded());
        assert_eq!(b.in_maps, set);
        assert_eq!(maps.generation, 2);
        assert_eq!(maps.runtime.len(), 2);
    }

    /// External audit SNS-007: stale rules (logins gone) are removed before
    /// the new ones are written, so a full map frees itself.
    #[test]
    fn removals_free_room_before_inserts() {
        let mut maps = FakeMaps {
            cap: 4,
            ..FakeMaps::default()
        };
        let mut old = RuleSet::default();
        for i in 30..34 {
            old.inodes.insert(ik(i), TREE_RUNTIME);
        }
        assert!(!apply_rules(&mut maps, &old, None).degraded());
        let mut next = RuleSet::default();
        next.inodes.insert(ik(1), FILE_SENSITIVE);
        next.inodes.insert(ik(2), TREE_CRITICAL);
        next.inodes.insert(ik(30), TREE_RUNTIME);
        let a = apply_rules(&mut maps, &next, Some(&old));
        assert!(!a.degraded(), "{a:?}");
        assert_eq!(maps.inodes, next.inodes);
        assert_eq!(a.in_maps, next);
    }

    /// External audit SNS-007: one ERROR and one signed record when rules
    /// are first refused, not one per minute; a WARN when the count moves,
    /// an INFO when all fit again.
    #[test]
    fn rule_health_reports_once_per_change() {
        let mut h = RuleHealth::default();
        let ok = Applied::default();
        let bad = |n| Applied {
            failed: n,
            ..Applied::default()
        };
        assert_eq!(h.note(&ok), RuleHealthChange::Same);
        assert_eq!(h.note(&bad(3)), RuleHealthChange::Degraded);
        assert_eq!(h.note(&bad(3)), RuleHealthChange::Same);
        assert_eq!(h.note(&bad(5)), RuleHealthChange::Changed);
        assert_eq!(h.note(&ok), RuleHealthChange::Recovered);
        let gen = Applied {
            generation_failed: true,
            ..Applied::default()
        };
        assert_eq!(h.note(&gen), RuleHealthChange::Degraded);
    }

    /// External audit SNS-007: the kernel maps hold the sizes this side
    /// reports; about 300 logins fit with room to spare.
    #[test]
    fn rule_maps_hold_hundreds_of_runtime_directories() {
        assert_eq!(RULE_CAPACITY, (4096, 1024, 64, 4096));
        assert!(CRED_NAME_RULES.len() <= OPEN_NAME_RULES_MAX as usize);
        let mut set = busy_set();
        for uid in 0..300u64 {
            set.inodes.insert(ik(1000 + uid), TREE_RUNTIME);
            set.runtime.insert(ik(1000 + uid), uid as u32);
        }
        let mut maps = FakeMaps {
            cap: RUNTIME_UIDS_MAX.min(OPEN_RULES_MAX) as usize,
            ..FakeMaps::default()
        };
        assert!(!apply_rules(&mut maps, &set, None).degraded());
    }

    /// Review 86: a FILE_CAP record is one capability grant: the permitted
    /// set from `count` (low) and `flags` (high), the effective flag and
    /// the revision from `magic_etc` in `mode`.
    #[test]
    fn a_file_cap_record_is_a_capability_grant() {
        let mut mounts = MountTable::default();
        mounts.roots.insert((7, 2), "/".into());
        mounts.loaded = Some(Instant::now());
        let mut r = record(
            open_reason::FILE_CAP,
            &["catcap", "lab48", "opt", "/"],
            (7, 2),
        );
        r.count = 1 << 2; // cap_dac_read_search
        r.flags = 1 << (39 - 32); // cap_bpf
        r.mode = 0x0200_0001; // revision 2, effective
        let ev = events_of(&r, &mut mounts);
        assert_eq!(ev.len(), 1, "{ev:?}");
        let Event::Fim(fe) = &ev[0] else {
            panic!("{ev:?}")
        };
        assert_eq!(fe.op, FimOp::CapabilitySet);
        assert_eq!(fe.path, "/opt/lab48/catcap");
        assert_eq!(
            fe.capability,
            Some(FileCapability {
                permitted: (1 << 2) | (1 << 39),
                effective: true,
                namespaced: false,
            })
        );
        r.mode = 0x0300_0000; // revision 3: namespaced, not effective
        let Event::Fim(fe) = &events_of(&r, &mut mounts)[0] else {
            panic!()
        };
        let cap = fe.capability.unwrap();
        assert!(cap.namespaced && !cap.effective);
    }
}
