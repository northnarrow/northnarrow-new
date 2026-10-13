//! Tappa 10.9 step 1 — userland half of the file-open sensor on LSM
//! `file_open` (`agent-ebpf/src/open_sensor.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §10).
//!
//! - [`RuleSet::build`] turns the posture's path lists, the telemetry
//!   probe directory, the home roots, the runtime directories and the
//!   credential names into the kernel's rule maps; [`RuleSet::apply`]
//!   writes them and bumps the directory-class generation.
//! - [`MountTable`] maps the root of a record's mount-relative path to a
//!   mount point, so consumers keep absolute paths.
//! - [`pump`] turns records into the events the rest of the agent reads
//!   today: `Event::FileOpen` (sensitive, critical, persistence, probe),
//!   `Event::Fim` `Opened` (credential stores, for NN-L-FIM-011..017) and
//!   `Event::MassWrite`.
//! - [`arm`] switches the kernel side on; the caller then drops the old
//!   `sys_enter_openat` tracepoint.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::Ebpf;
use common::wire::open_sensor::{
    open_class::{
        CHILDREN_PROBE, CHILD_FILES, DIR_HAS_FILES, FILE_CRITICAL, FILE_PERSIST, FILE_SENSITIVE,
        LEAF_CRED, LEAVES_CRED, SUBTREE, TREE_CARVEOUT, TREE_CRED, TREE_CRITICAL, TREE_HOME,
        TREE_PERSIST, TREE_RUNTIME,
    },
    open_reason, ChildRuleKey, OpenRecordRaw, OPEN_NAME_LEN, OPEN_PATH_SLOTS, OPEN_PATH_SLOT_LEN,
    OPEN_SENSOR_ARMED,
};
use common::wire::{FileCapability, FimEvent, FimOp, InodeKey};
use common::Event;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::anti_tamper::filesystem::{stat_dev_to_kernel_dev, AyaInodeKey};

/// The ring of interesting opens.
pub const OPEN_SENSOR_EVENTS_MAP: &str = "OPEN_SENSOR_EVENTS";

/// The `sys_enter_openat` program's switch (review 69): slot 0 non-zero =
/// the tracepoint emits one record per `openat`.
pub const FILE_OPEN_TP_ON_MAP: &str = "FILE_OPEN_TP_ON";

static TRACEPOINT_MODE: AtomicBool = AtomicBool::new(false);

/// `--file-open-sensor tracepoint`; set before the multiplexer starts.
pub fn want_tracepoint(on: bool) {
    TRACEPOINT_MODE.store(on, Ordering::Relaxed);
}

/// Whether `sys_enter_openat` must emit from the start.
pub fn tracepoint_wanted() -> bool {
    TRACEPOINT_MODE.load(Ordering::Relaxed)
}

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
    /// of every account with a uid of 1000 or more, and the runtime
    /// directories under `/run/user`.
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

/// `/root` plus the home of every `/etc/passwd` account with uid ≥ 1000
/// (`nobody`'s 65534 excluded), each once.
pub fn home_roots(passwd: &str) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/root")];
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        if !(1000..65534).contains(&uid) || !f[5].starts_with('/') || f[5] == "/" {
            continue;
        }
        let p = PathBuf::from(f[5]);
        if !out.contains(&p) {
            out.push(p);
        }
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
            set.add_path(p, 0, TREE_CARVEOUT);
        }
        let probe = format!("{}/", inputs.probe_dir.display());
        set.add_path(&probe, 0, CHILDREN_PROBE);
        for h in &inputs.homes {
            if let Ok(m) = std::fs::metadata(h) {
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

/// Owned handles on the sensor's rule maps (taken out of the object, so a
/// task can refresh them).
pub struct OpenSensorMaps {
    rules: BpfHashMap<MapData, AyaInodeKey, u32>,
    children: BpfHashMap<MapData, AyaChildKey, u32>,
    names: BpfHashMap<MapData, [u8; 2 * OPEN_NAME_LEN], u32>,
    runtime: BpfHashMap<MapData, AyaInodeKey, u32>,
    generation: Array<MapData, u32>,
    armed: Array<MapData, u32>,
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
            armed: Array::try_from(take(ebpf, "OPEN_SENSOR")?)?,
        })
    }

    /// Write `set`, remove what `previous` had and `set` does not, and
    /// bump the directory-class generation so no cached class survives a
    /// rule change.
    pub fn apply(&mut self, set: &RuleSet, previous: Option<&RuleSet>) -> Result<()> {
        for (k, v) in &set.inodes {
            self.rules.insert(AyaInodeKey(*k), *v, 0)?;
        }
        for (k, v) in &set.children {
            self.children.insert(AyaChildKey(*k), *v, 0)?;
        }
        for (k, v) in &set.names {
            self.names.insert(*k, *v, 0)?;
        }
        for (k, v) in &set.runtime {
            self.runtime.insert(AyaInodeKey(*k), *v, 0)?;
        }
        if let Some(prev) = previous {
            for k in prev.inodes.keys().filter(|k| !set.inodes.contains_key(k)) {
                let _ = self.rules.remove(&AyaInodeKey(*k));
            }
            for k in prev
                .children
                .keys()
                .filter(|k| !set.children.contains_key(k))
            {
                let _ = self.children.remove(&AyaChildKey(*k));
            }
            for k in prev.runtime.keys().filter(|k| !set.runtime.contains_key(k)) {
                let _ = self.runtime.remove(&AyaInodeKey(*k));
            }
        }
        self.bump_generation()
    }

    /// Invalidate every cached directory class.
    pub fn bump_generation(&mut self) -> Result<()> {
        let cur = self.generation.get(&0, 0).unwrap_or(0);
        self.generation.set(0, cur.wrapping_add(1), 0)?;
        Ok(())
    }

    /// Switch the kernel side on (or off): from now on the FIM
    /// `file_open` observer classifies every open.
    pub fn arm(&mut self, on: bool) -> Result<()> {
        self.armed
            .set(0, if on { OPEN_SENSOR_ARMED } else { 0 }, 0)?;
        Ok(())
    }
}

pub fn take_ringbuf(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    RingBuf::try_from(take(ebpf, OPEN_SENSOR_EVENTS_MAP)?)
        .map_err(|e| anyhow!("{OPEN_SENSOR_EVENTS_MAP} is not a RINGBUF: {e}"))
}

// ───────────────────────────── paths ─────────────────────────────

/// Filesystem roots → mount points, from `/proc/self/mountinfo` and a
/// `stat()` of each mount point (the key the kernel records for the top
/// of a path walk).
#[derive(Debug, Default)]
pub struct MountTable {
    roots: HashMap<(u64, u64), String>,
    loaded: Option<Instant>,
}

/// Refresh on a miss at most this often.
const MOUNT_REFRESH_MIN: Duration = Duration::from_secs(2);

impl MountTable {
    pub fn load() -> Self {
        let mut t = MountTable::default();
        t.refresh();
        t
    }

    pub fn refresh(&mut self) {
        let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
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
    }

    /// Absolute path of `rel` (mount-relative, starting with `/`) under
    /// the filesystem root `root`, refreshing the table on a miss.
    pub fn absolute(&mut self, root: (u64, u64), rel: &str) -> Option<String> {
        if root == (0, 0) {
            return None;
        }
        if !self.roots.contains_key(&root)
            && self.loaded.is_none_or(|t| t.elapsed() >= MOUNT_REFRESH_MIN)
        {
            self.refresh();
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

fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = u32::from(b[i + 1] - b'0') * 64
                + u32::from(b[i + 2] - b'0') * 8
                + u32::from(b[i + 3] - b'0');
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The record's path components, leaf → root.
fn components(r: &OpenRecordRaw) -> Vec<String> {
    (0..(r.path_n as usize).min(OPEN_PATH_SLOTS))
        .map(|i| {
            let slot = &r.path[i * OPEN_PATH_SLOT_LEN..(i + 1) * OPEN_PATH_SLOT_LEN];
            let end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
            String::from_utf8_lossy(&slot[..end]).into_owned()
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

/// The events one record stands for.
pub fn events_of(r: &OpenRecordRaw, mounts: &mut MountTable) -> Vec<Event> {
    let rel = relative_path(r);
    let filename = match mounts.absolute((r.root_dev, r.root_ino), &rel) {
        Some(abs) => abs,
        None if r.path_truncated != 0 => format!("…{rel}"),
        None => rel,
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
        }));
    }
    // External audit POS-002: one event per crossing; an open crossing
    // both thresholds is one event, an overwrite one.
    if r.reason & (open_reason::MASS_WRITE | open_reason::MASS_OVERWRITE) != 0 {
        out.push(Event::MassWrite {
            pid: r.pid,
            uid: r.uid,
            comm,
            count: r.count,
            filename,
            timestamp_ns: r.timestamp_ns,
            overwrites: r.reason & open_reason::MASS_OVERWRITE != 0,
        });
    }
    out
}

/// Drain the ring into the agent's event channel until the receiver goes
/// away.
pub async fn pump(ring: RingBuf<MapData>, tx: mpsc::Sender<Event>) {
    let mut fd = match AsyncFd::new(ring) {
        Ok(fd) => fd,
        Err(e) => {
            warn!(error = %e, "open sensor: cannot poll its ring — no file-open events");
            return;
        }
    };
    let mut mounts = MountTable::load();
    let size = std::mem::size_of::<OpenRecordRaw>();
    loop {
        let mut guard = match fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "open sensor: ring wait failed");
                return;
            }
        };
        let mut batch = Vec::new();
        {
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if item.len() < size {
                    debug!(len = item.len(), "open sensor: short record skipped");
                    continue;
                }
                batch.push(bytemuck::pod_read_unaligned::<OpenRecordRaw>(&item[..size]));
            }
        }
        guard.clear_ready();
        for r in &batch {
            for ev in events_of(r, &mut mounts) {
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Rebuild the rules from the host (new homes, runtime directories, paths
/// created since) and write the difference; the new set when it changed.
pub fn refresh(
    maps: &mut OpenSensorMaps,
    current: &RuleSet,
    carveout_extras: &[String],
) -> Result<Option<RuleSet>> {
    let next = RuleSet::build(&RuleInputs::from_host(carveout_extras));
    if next == *current {
        return Ok(None);
    }
    maps.apply(&next, Some(current))?;
    info!(
        inodes = next.inodes.len(),
        children = next.children.len(),
        runtime_dirs = next.runtime.len(),
        "open sensor: rules refreshed"
    );
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_roots_reads_regular_accounts_only() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      alice:x:1000:1000::/home/alice:/bin/bash\n\
                      bob:x:1001:1001::/srv/bob:/bin/sh\n\
                      nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
                      broken line\n";
        assert_eq!(
            home_roots(passwd),
            vec![
                PathBuf::from("/root"),
                PathBuf::from("/home/alice"),
                PathBuf::from("/srv/bob")
            ]
        );
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
        let root = t.path();
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
        // An unknown root keeps the mount-relative path.
        let r = record(open_reason::CRED, &["credentials", ".aws", "/"], (5, 5));
        assert!(
            matches!(&events_of(&r, &mut mounts)[0], Event::Fim(fe) if fe.path == "/.aws/credentials")
        );
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
