//! Lab PR 236 (C12): the signed per-rule response policy.
//!
//! A policy maps a rule to a mode — `off`, `audit` (record only), `alert`
//! (record and count, no response) or `enforce` (the rule's own response, a
//! held kill included) — and may exempt an actor from a rule: an executable
//! of a root-owned system tree with its SHA-256, a cgroup or systemd unit,
//! a uid; never a process name. Without a policy every rule keeps its
//! built-in behaviour ([`Mode`] absent): its own response, the kills the
//! decision of 21/10/2026 holds ([`super::response_policy`]) held.
//!
//! The policy is the signed overlay `rule-policy.local`
//! ([`OverlayKind::RulePolicy`](common::wire::admin_signed_payload::OverlayKind::RulePolicy)):
//! one directive per line, any bad line refuses the whole file
//! ([`parse`]). The engine reads the active policy through a
//! [`PolicyHandle`]; `nn-admin policy set` swaps it between two events.
//! Design: `docs/design/MULTI_MATCH_AND_RULE_POLICY.md`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};

use super::catalogue;

/// What the policy makes of a rule's match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// Dropped from the decision (the rule still runs: its state is kept).
    Off,
    /// Recorded only: listed in the record, `Log`, not counted.
    Audit,
    /// Recorded and counted (severity, primary rule), `Log`.
    Alert,
    /// The rule's own response, a held kill included.
    Enforce,
}

impl Mode {
    pub fn keyword(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Audit => "audit",
            Mode::Alert => "alert",
            Mode::Enforce => "enforce",
        }
    }

    fn from_keyword(s: &str) -> Option<Self> {
        Some(match s {
            "off" => Mode::Off,
            "audit" => Mode::Audit,
            "alert" => Mode::Alert,
            "enforce" => Mode::Enforce,
            _ => return None,
        })
    }
}

/// An actor a rule's match is not acted on for: the match is `audit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exemption {
    /// The acting uid (never 0).
    Uid(u32),
    /// An executable of a root-owned system tree, by path and content.
    Exe { path: String, sha256: [u8; 32] },
    /// The process's cgroup v2 path (a `.service` or `.scope`).
    Cgroup(String),
    /// The systemd unit of the process's cgroup (`foo.service`).
    Unit(String),
}

impl fmt::Display for Exemption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Exemption::Uid(u) => write!(f, "uid {u}"),
            Exemption::Exe { path, sha256 } => write!(f, "exe {path} sha256 {}", hex(sha256)),
            Exemption::Cgroup(c) => write!(f, "cgroup {c}"),
            Exemption::Unit(u) => write!(f, "unit {u}"),
        }
    }
}

/// Where the agent reads the policy (`--rule-policy-local`).
pub const DEFAULT_LOCAL: &str = "/etc/northnarrow/rule-policy.local";
/// The signed audit row of the policy put in force at boot.
pub const AUDIT_OP_LOADED: &str = "rule_policy_loaded";

/// Exemptions one rule may carry (a bound on the per-match cost).
pub const MAX_EXEMPTIONS_PER_RULE: usize = 64;
/// Lines a policy may have.
pub const MAX_LINES: usize = 4096;

/// The rules decided outside the engine: a mode for them would do nothing.
const OUTSIDE_ENGINE: &[&str] = &[
    "NN-L-AT-",
    "NN-L-EPG-",
    "NN-L-EXECPOL-",
    "NN-L-EXECENV-",
    "NN-L-EXECQ-",
];

/// The one rule `combat-without-corroboration` takes.
pub const RANSOMWARE_RULE: &str = "NN-L-IMP-001_RansomwareEncryption";

/// A parsed policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulePolicy {
    modes: BTreeMap<&'static str, Mode>,
    exemptions: BTreeMap<&'static str, Vec<Exemption>>,
    /// `combat-without-corroboration NN-L-IMP-001`.
    pub ransomware_combat_without_corroboration: bool,
    /// Where it came from (`built-in defaults`, `<path> (signed, sha256 …)`).
    pub source: String,
}

impl RulePolicy {
    /// No directive: every rule built in.
    pub fn builtin() -> Self {
        Self {
            source: "built-in defaults".to_string(),
            ..Self::default()
        }
    }

    /// The mode the policy gives `rule_id`, `None` = built in.
    pub fn mode(&self, rule_id: &str) -> Option<Mode> {
        self.modes.get(rule_id).copied()
    }

    /// The exemptions of `rule_id`.
    pub fn exemptions(&self, rule_id: &str) -> &[Exemption] {
        self.exemptions.get(rule_id).map_or(&[], Vec::as_slice)
    }

    /// The rules with a mode, by id.
    pub fn modes(&self) -> impl Iterator<Item = (&'static str, Mode)> + '_ {
        self.modes.iter().map(|(k, v)| (*k, *v))
    }

    /// The rules with exemptions, by id.
    pub fn all_exemptions(&self) -> impl Iterator<Item = (&'static str, &[Exemption])> + '_ {
        self.exemptions.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    /// No directive at all.
    pub fn is_builtin(&self) -> bool {
        self.modes.is_empty()
            && self.exemptions.is_empty()
            && !self.ransomware_combat_without_corroboration
    }

    /// One line for the logs and the audit row.
    pub fn summary(&self) -> String {
        let count = |m: Mode| self.modes.values().filter(|x| **x == m).count();
        format!(
            "{} enforce, {} alert, {} audit, {} off, {} exemptions on {} rules, \
             ransomware COMBAT without corroboration {}",
            count(Mode::Enforce),
            count(Mode::Alert),
            count(Mode::Audit),
            count(Mode::Off),
            self.exemptions.values().map(Vec::len).sum::<usize>(),
            self.exemptions.len(),
            if self.ransomware_combat_without_corroboration {
                "on"
            } else {
                "off"
            }
        )
    }

    /// The policy as a file [`parse`] reads back to the same policy.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (r, m) in &self.modes {
            out.push_str(&format!("{} {r}\n", m.keyword()));
        }
        for (r, ex) in &self.exemptions {
            for e in ex {
                out.push_str(&format!("exempt {r} {e}\n"));
            }
        }
        if self.ransomware_combat_without_corroboration {
            out.push_str(&format!("combat-without-corroboration {RANSOMWARE_RULE}\n"));
        }
        out
    }
}

/// The table `nn-admin policy show` prints: the rules the policy names,
/// their exemptions, the posture flag, and the built-in switches (what a
/// rule without a line keeps held).
pub fn show(p: &RulePolicy) -> String {
    let mut out = format!("source: {}\n", p.source);
    if p.is_builtin() {
        out.push_str("every rule: builtin (its own response; the held kills below held)\n");
    } else {
        out.push_str(
            "every rule not listed: builtin (its own response; the held kills below held)\n",
        );
        for (r, m) in p.modes() {
            out.push_str(&format!("{:<8} {r}\n", m.keyword()));
        }
        for (r, ex) in p.all_exemptions() {
            for e in ex {
                out.push_str(&format!("exempt   {r}: {e}\n"));
            }
        }
    }
    out.push_str(&format!(
        "ransomware COMBAT without corroboration: {}\n",
        if p.ransomware_combat_without_corroboration {
            "on (combat-without-corroboration NN-L-IMP-001)"
        } else {
            "off (built-in default)"
        }
    ));
    out.push_str(
        "legacy ceiling: a rule not set to enforce never runs more than the first-match \
         engine ran on the same event (lifted per rule by `enforce <rule>`)\n",
    );
    out.push_str("built-in held responses (given back by `enforce <rule>` for that rule):\n");
    for s in super::response_policy::ALL {
        out.push_str(&format!("  held: {}\n", s.held));
    }
    out
}

/// A line that refuses the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub line: usize,
    pub why: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.why)
    }
}

impl std::error::Error for PolicyError {}

/// The full id of the rule `name` names — its full id, or its short id
/// (`NN-L-IMP-001`, `R020`) — among the rules the engine decides.
pub fn resolve_rule(name: &str) -> Result<&'static str, String> {
    if OUTSIDE_ENGINE.iter().any(|p| name.starts_with(p)) {
        return Err(format!(
            "{name} is decided outside the rule engine (anti-tamper, exploit guard, exec \
             policy, exec quarantine): the per-rule policy does not apply to it"
        ));
    }
    let found: Vec<&'static str> = catalogue::docs()
        .map(|d| d.id)
        .filter(|id| *id == name || short_id(id) == name)
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("unknown rule `{name}`")),
        _ => Err(format!(
            "`{name}` names several rules: {}",
            found.join(", ")
        )),
    }
}

/// `NN-L-IMP-001` of `NN-L-IMP-001_RansomwareEncryption`, `R020` of
/// `R020_ShellWithSocketStdio`.
pub fn short_id(id: &str) -> &str {
    id.split_once('_').map_or(id, |(s, _)| s)
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A unit name: `[A-Za-z0-9:_.\\@-]+` ending in `.service` or `.scope`.
fn valid_unit(u: &str) -> bool {
    let stem = u
        .strip_suffix(".service")
        .or_else(|| u.strip_suffix(".scope"));
    stem.is_some_and(|s| {
        !s.is_empty()
            && u.len() <= 255
            && u.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":_.\\@-".contains(&b))
    })
}

/// `exe <path>`: absolute, canonical in form, in a root-owned system tree.
fn valid_exe_path(p: &str) -> Result<(), String> {
    if !p.starts_with('/') {
        return Err(format!("exe {p}: not an absolute path"));
    }
    if p.split('/').any(|c| c == ".." || c == ".") || p.contains("//") || p.ends_with('/') {
        return Err(format!("exe {p}: not a canonical path"));
    }
    if !crate::posture::lineage::in_system_tree(p) {
        return Err(format!(
            "exe {p}: not in a root-owned system tree (/usr, /opt, /bin, /sbin, /lib, /lib64, \
             /snap, /nix/store)"
        ));
    }
    Ok(())
}

/// `cgroup <path>`: absolute, canonical, its last component a unit, not the
/// agent's own containment slice.
fn valid_cgroup(p: &str) -> Result<(), String> {
    if !p.starts_with('/') || p.split('/').any(|c| c == ".." || c == ".") || p.contains("//") {
        return Err(format!("cgroup {p}: not an absolute canonical cgroup path"));
    }
    let last = p.rsplit('/').next().unwrap_or("");
    if !valid_unit(last) {
        return Err(format!(
            "cgroup {p}: its last component names no .service or .scope (a slice or the root \
             would exempt every process under it)"
        ));
    }
    if p == "/northnarrow.slice" || p.starts_with("/northnarrow.slice/") {
        return Err(format!(
            "cgroup {p}: the agent's containment cgroup holds contained processes"
        ));
    }
    Ok(())
}

/// Parse a policy file. Any bad line refuses the whole file.
pub fn parse(text: &str) -> Result<RulePolicy, PolicyError> {
    let mut p = RulePolicy::default();
    let mut lines = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        lines += 1;
        if lines > MAX_LINES {
            return Err(PolicyError {
                line,
                why: format!("more than {MAX_LINES} lines"),
            });
        }
        let err = |why: String| PolicyError { line, why };
        let content = raw.split_once('#').map_or(raw, |(c, _)| c).trim();
        if content.is_empty() {
            continue;
        }
        if content.chars().any(char::is_control) {
            return Err(err("a control character".to_string()));
        }
        let words: Vec<&str> = content.split_whitespace().collect();
        match words.as_slice() {
            [kw, rule] if Mode::from_keyword(kw).is_some() => {
                let mode = Mode::from_keyword(kw).expect("checked");
                let id = resolve_rule(rule).map_err(err)?;
                if let Some(prev) = p.modes.insert(id, mode) {
                    return Err(err(format!(
                        "{id} already has a mode ({}): one mode per rule",
                        prev.keyword()
                    )));
                }
            }
            [kw, ..] if Mode::from_keyword(kw).is_some() => {
                return Err(err(format!("`{kw}` takes one rule: `{kw} <rule>`")));
            }
            ["exempt", rule, kind, rest @ ..] => {
                let id = resolve_rule(rule).map_err(err)?;
                let ex = match (*kind, rest) {
                    ("uid", [u]) => {
                        let uid: u32 = u.parse().map_err(|_| err(format!("uid {u}: not a uid")))?;
                        if uid == 0 {
                            return Err(err(
                                "uid 0: exempting root is turning the rule off — say `audit` \
                                 or `off` instead"
                                    .to_string(),
                            ));
                        }
                        if uid == u32::MAX {
                            return Err(err(format!("uid {u}: the invalid uid")));
                        }
                        Exemption::Uid(uid)
                    }
                    ("exe", [path, "sha256", digest]) => {
                        valid_exe_path(path).map_err(err)?;
                        let sha256 = unhex32(digest).ok_or_else(|| {
                            err(format!("sha256 {digest}: not 64 hexadecimal digits"))
                        })?;
                        Exemption::Exe {
                            path: path.to_string(),
                            sha256,
                        }
                    }
                    ("exe", _) => {
                        return Err(err(
                            "exe takes a path and its digest: `exe <path> sha256 <hex>` (a path \
                             alone is never an exemption)"
                                .to_string(),
                        ))
                    }
                    ("cgroup", [path]) => {
                        valid_cgroup(path).map_err(err)?;
                        Exemption::Cgroup(path.to_string())
                    }
                    ("unit", [u]) => {
                        if !valid_unit(u) {
                            return Err(err(format!("unit {u}: not a .service or .scope name")));
                        }
                        Exemption::Unit(u.to_string())
                    }
                    ("comm" | "name" | "process" | "argv", _) => {
                        return Err(err(format!(
                            "an exemption by {kind} is refused: any user can give a process \
                             any name — exempt an executable with its digest, a unit, a cgroup \
                             or a uid"
                        )))
                    }
                    (k, _) => {
                        return Err(err(format!(
                            "exemption `{k}`: one of uid, exe, cgroup, unit, with its value"
                        )))
                    }
                };
                let list = p.exemptions.entry(id).or_default();
                if list.contains(&ex) {
                    return Err(err(format!("{id}: `{ex}` twice")));
                }
                if list.len() >= MAX_EXEMPTIONS_PER_RULE {
                    return Err(err(format!(
                        "{id}: more than {MAX_EXEMPTIONS_PER_RULE} exemptions"
                    )));
                }
                list.push(ex);
            }
            ["exempt", ..] => {
                return Err(err(
                    "`exempt <rule> uid|exe|cgroup|unit <value>`".to_string()
                ))
            }
            ["combat-without-corroboration", rule] => {
                let id = resolve_rule(rule).map_err(err)?;
                if id != RANSOMWARE_RULE {
                    return Err(err(format!(
                        "combat-without-corroboration applies to {RANSOMWARE_RULE} only"
                    )));
                }
                if p.ransomware_combat_without_corroboration {
                    return Err(err("combat-without-corroboration twice".to_string()));
                }
                p.ransomware_combat_without_corroboration = true;
            }
            [kw, ..] => {
                return Err(err(format!(
                    "unknown directive `{kw}`: enforce, alert, audit, off, exempt, \
                     combat-without-corroboration"
                )))
            }
            [] => unreachable!("empty content skipped"),
        }
    }
    Ok(p)
}

/// The active policy, shared by the engine and the admin socket.
#[derive(Debug, Clone)]
pub struct PolicyHandle(Arc<RwLock<Arc<RulePolicy>>>);

impl PolicyHandle {
    pub fn new(p: RulePolicy) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(p))))
    }

    /// The policy in force now (one read per event).
    pub fn current(&self) -> Arc<RulePolicy> {
        Arc::clone(&self.0.read())
    }

    /// Put `p` in force (between two events); the previous one back.
    pub fn install(&self, p: RulePolicy) -> Arc<RulePolicy> {
        std::mem::replace(&mut *self.0.write(), Arc::new(p))
    }
}

impl Default for PolicyHandle {
    fn default() -> Self {
        Self::new(RulePolicy::builtin())
    }
}

/// The agent's policy (production: `main.rs` installs the boot policy,
/// `nn-admin policy set` the next).
pub fn global() -> &'static PolicyHandle {
    static G: OnceLock<PolicyHandle> = OnceLock::new();
    G.get_or_init(PolicyHandle::default)
}

/// Put `p` in force for the agent: the [`global`] handle the production
/// engine reads, and the posture's ransomware flag
/// ([`common::posture_types::ransomware_combat_without_corroboration`]).
pub fn install_global(p: RulePolicy) -> Arc<RulePolicy> {
    common::posture_types::set_ransomware_combat_without_corroboration(
        p.ransomware_combat_without_corroboration,
    );
    global().install(p)
}

/// What the boot read made of the overlay.
#[derive(Debug)]
pub struct BootPolicy {
    pub policy: RulePolicy,
    /// A signed file that did not parse: the built-in defaults are in force.
    pub degraded: Option<String>,
}

/// The boot policy from the overlay gate's verified text (`None`: absent or
/// refused — the built-in defaults).
pub fn boot_policy(verified: Option<(&Path, &str)>) -> BootPolicy {
    match verified {
        None => BootPolicy {
            policy: RulePolicy::builtin(),
            degraded: None,
        },
        Some((path, text)) => match parse(text) {
            Ok(mut p) => {
                p.source = format!(
                    "{} (signed, sha256 {})",
                    path.display(),
                    hex(&Sha256::digest(text.as_bytes()))
                );
                BootPolicy {
                    policy: p,
                    degraded: None,
                }
            }
            Err(e) => BootPolicy {
                policy: RulePolicy::builtin(),
                degraded: Some(format!(
                    "{}: {e} — the built-in defaults are in force",
                    path.display()
                )),
            },
        },
    }
}

// ── exemption facts ──────────────────────────────────────────────────

/// What an exemption check reads about a process. Fail closed: `None`
/// when a fact cannot be read, and the match is then not exempt.
pub trait ActorFacts: Send + Sync {
    /// The real uid of `pid`.
    fn uid(&self, pid: u32) -> Option<u32>;
    /// The cgroup v2 path of `pid`.
    fn cgroup(&self, pid: u32) -> Option<String>;
    /// `/proc/<pid>/exe` opened: its path, when it is a root-owned file of
    /// a root-owned tree no one else can write, and its SHA-256.
    fn trusted_exe(&self, pid: u32) -> Option<(String, [u8; 32])>;
}

/// [`ActorFacts`] read from a `/proc` (the host's, or an empty one in the
/// golden replay).
pub struct ProcFacts {
    root: PathBuf,
    hashes: Mutex<HashCache>,
}

/// Executables hashed, by identity; at most [`HASH_CACHE_CAP`].
#[derive(Default)]
struct HashCache {
    map: HashMap<FileKey, [u8; 32]>,
    order: std::collections::VecDeque<FileKey>,
}

const HASH_CACHE_CAP: usize = 64;
/// Larger executables are not hashed (not exempt).
const MAX_HASHED_BYTES: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl ProcFacts {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            root: proc_root.into(),
            hashes: Mutex::new(HashCache::default()),
        }
    }

    fn hash_file(&self, f: &mut std::fs::File, key: FileKey) -> Option<[u8; 32]> {
        use std::io::Read as _;
        if let Some(h) = self.hashes.lock().map.get(&key) {
            return Some(*h);
        }
        if key.size > MAX_HASHED_BYTES {
            return None;
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(_) => return None,
            }
        }
        let digest: [u8; 32] = h.finalize().into();
        let mut c = self.hashes.lock();
        if c.map.insert(key, digest).is_none() {
            c.order.push_back(key);
            while c.order.len() > HASH_CACHE_CAP {
                if let Some(old) = c.order.pop_front() {
                    c.map.remove(&old);
                }
            }
        }
        Some(digest)
    }
}

impl Default for ProcFacts {
    fn default() -> Self {
        Self::new("/proc")
    }
}

/// Root-owned and writable by no one else.
fn root_only(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.uid() == 0 && m.mode() & 0o022 == 0
}

impl ActorFacts for ProcFacts {
    fn uid(&self, pid: u32) -> Option<u32> {
        let s = std::fs::read_to_string(self.root.join(pid.to_string()).join("status")).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|u| u.parse().ok())
    }

    fn cgroup(&self, pid: u32) -> Option<String> {
        let s = std::fs::read_to_string(self.root.join(pid.to_string()).join("cgroup")).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(str::to_string)
    }

    fn trusted_exe(&self, pid: u32) -> Option<(String, [u8; 32])> {
        use std::os::unix::fs::MetadataExt;
        let link = self.root.join(pid.to_string()).join("exe");
        let path = std::fs::read_link(&link).ok()?;
        let path_s = path.to_str()?.to_string();
        if !crate::posture::lineage::in_system_tree(&path_s) {
            return None;
        }
        let mut f = std::fs::File::open(&link).ok()?;
        let m = f.metadata().ok()?;
        if !m.file_type().is_file() || !root_only(&m) {
            return None;
        }
        // The opened file is the one at the path it names now.
        let at_path = std::fs::symlink_metadata(&path).ok()?;
        if at_path.dev() != m.dev() || at_path.ino() != m.ino() {
            return None;
        }
        let mut dir = path.parent();
        while let Some(d) = dir {
            if !root_only(&std::fs::symlink_metadata(d).ok()?) {
                return None;
            }
            dir = d.parent();
        }
        let key = FileKey {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        };
        let digest = self.hash_file(&mut f, key)?;
        Some((path_s, digest))
    }
}

/// The unit a cgroup path names: its last `.service` / `.scope` component.
fn unit_of(cgroup: &str) -> Option<&str> {
    cgroup
        .rsplit('/')
        .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
}

/// The exemption among `ex` that covers process `pid` (acting as `uid`
/// when the event says so), if any. Facts are read only for the kinds
/// present, at most once each.
pub fn exempt(
    ex: &[Exemption],
    pid: u32,
    event_uid: Option<u32>,
    facts: &dyn ActorFacts,
) -> Option<String> {
    if ex.is_empty() {
        return None;
    }
    let mut uid: Option<Option<u32>> = None;
    let mut cgroup: Option<Option<String>> = None;
    let mut exe: Option<Option<(String, [u8; 32])>> = None;
    for e in ex {
        let hit = match e {
            Exemption::Uid(u) => {
                let got = *uid.get_or_insert_with(|| event_uid.or_else(|| facts.uid(pid)));
                got == Some(*u)
            }
            Exemption::Cgroup(c) => cgroup
                .get_or_insert_with(|| facts.cgroup(pid))
                .as_deref()
                .is_some_and(|g| g == c),
            Exemption::Unit(u) => cgroup
                .get_or_insert_with(|| facts.cgroup(pid))
                .as_deref()
                .and_then(unit_of)
                .is_some_and(|g| g == u),
            Exemption::Exe { path, sha256 } => exe
                .get_or_insert_with(|| facts.trusted_exe(pid))
                .as_ref()
                .is_some_and(|(p, h)| p == path && h == sha256),
        };
        if hit {
            return Some(e.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMP: &str = "NN-L-IMP-001_RansomwareEncryption";
    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn refused(text: &str) -> PolicyError {
        parse(text).expect_err(text)
    }

    #[test]
    fn an_empty_file_is_the_builtin_policy() {
        let p = parse("# nothing\n\n   \n").unwrap();
        assert!(p.is_builtin());
        assert_eq!(p.mode(IMP), None);
    }

    #[test]
    fn modes_by_full_and_short_id() {
        let p = parse(
            "enforce NN-L-IMP-001\nalert R020_ShellWithSocketStdio\naudit NN-L-NET-007\n\
             off R008  # comment\n",
        )
        .unwrap();
        assert_eq!(p.mode(IMP), Some(Mode::Enforce));
        assert_eq!(p.mode("R020_ShellWithSocketStdio"), Some(Mode::Alert));
        assert_eq!(
            p.mode(resolve_rule("NN-L-NET-007").unwrap()),
            Some(Mode::Audit)
        );
        assert_eq!(p.mode(resolve_rule("R008").unwrap()), Some(Mode::Off));
        // The rendering reads back to the same policy.
        assert_eq!(parse(&p.render()).unwrap(), p);
    }

    #[test]
    fn every_bad_line_refuses_the_file_with_its_number() {
        for (text, line, what) in [
            ("enforce NN-L-NOPE-999\n", 1, "unknown rule"),
            ("enforce\n", 1, "takes one rule"),
            ("enforce R020 R001\n", 1, "takes one rule"),
            ("allow R020\n", 1, "unknown directive"),
            ("enforce R020\nalert R020\n", 2, "one mode per rule"),
            ("\nenforce NN-L-AT-001\n", 2, "outside the rule engine"),
            ("off NN-L-EPG-001\n", 1, "outside the rule engine"),
            ("exempt R020 uid 0\n", 1, "uid 0"),
            ("exempt R020 uid -1\n", 1, "not a uid"),
            ("exempt R020 uid 4294967295\n", 1, "invalid uid"),
            ("exempt R020 uid\n", 1, "exemption `uid`"),
            ("exempt R020\n", 1, "exempt <rule>"),
            ("exempt R020 exe /usr/bin/x\n", 1, "a path alone"),
            (
                &format!("exempt R020 exe /tmp/x sha256 {SHA}\n"),
                1,
                "system tree",
            ),
            (
                &format!("exempt R020 exe /usr/bin/../../tmp/x sha256 {SHA}\n"),
                1,
                "canonical",
            ),
            (
                &format!("exempt R020 exe usr/bin/x sha256 {SHA}\n"),
                1,
                "absolute",
            ),
            ("exempt R020 exe /usr/bin/x sha256 abcd\n", 1, "64 hexadecimal"),
            ("exempt R020 cgroup /system.slice\n", 1, "names no .service"),
            ("exempt R020 cgroup /\n", 1, "names no .service"),
            ("exempt R020 cgroup system.slice/a.service\n", 1, "absolute"),
            (
                "exempt R020 cgroup /northnarrow.slice/blocked.scope\n",
                1,
                "containment",
            ),
            ("exempt R020 unit sshd\n", 1, "not a .service"),
            ("exempt R020 unit a/b.service\n", 1, "not a .service"),
            ("exempt R020 bogus 1\n", 1, "exemption `bogus`"),
            ("exempt R020 uid 1000\nexempt R020 uid 1000\n", 2, "twice"),
            ("combat-without-corroboration R020\n", 1, "applies to"),
            (
                "combat-without-corroboration NN-L-IMP-001\ncombat-without-corroboration NN-L-IMP-001\n",
                2,
                "twice",
            ),
            ("enforce R020\x07\n", 1, "control character"),
        ] {
            let e = refused(text);
            assert_eq!(e.line, line, "{text:?}: {e}");
            assert!(e.why.contains(what), "{text:?}: {e}");
        }
    }

    /// Never by name: comm, name, process or argv refuse the file.
    #[test]
    fn an_exemption_by_name_is_refused() {
        for kind in ["comm", "name", "process", "argv"] {
            let e = refused(&format!("exempt R020 {kind} sshd\n"));
            assert!(e.why.contains("any user can give a process"), "{e}");
        }
    }

    #[test]
    fn exemptions_are_bounded_per_rule() {
        let mut text = String::new();
        for u in 1..=MAX_EXEMPTIONS_PER_RULE as u32 {
            text.push_str(&format!("exempt R020 uid {u}\n"));
        }
        assert!(parse(&text).is_ok());
        text.push_str("exempt R020 uid 100000\n");
        assert!(refused(&text).why.contains("more than"));
        let many = "# x\n".repeat(MAX_LINES + 1);
        assert!(refused(&many).why.contains("lines"));
    }

    #[test]
    fn the_posture_directive() {
        let p = parse("combat-without-corroboration NN-L-IMP-001\n").unwrap();
        assert!(p.ransomware_combat_without_corroboration);
        assert!(!p.is_builtin());
    }

    /// Every rule the engine decides is named by a unique short id, and
    /// the catalogue names every engine rule (the policy resolves names
    /// through it).
    #[test]
    fn every_engine_rule_resolves_by_its_short_id() {
        let proc = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::new(proc.path());
        let engine = crate::decision::replay::engine(crate::decision::replay::HostParts {
            configs: Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../configs")),
            proc_root: proc.path(),
            lineage: lineage.clone(),
            ransom: Arc::new(crate::impact::RansomTracker::new(lineage)),
            resolvers: Vec::new(),
            policy: RulePolicy::builtin(),
        });
        assert!(engine.rule_count() > 50);
        for id in engine.rule_ids() {
            assert_eq!(resolve_rule(id), Ok(id), "{id}");
            assert_eq!(resolve_rule(short_id(id)), Ok(id), "{id}");
        }
    }

    struct Facts {
        uid: Option<u32>,
        cgroup: Option<&'static str>,
        exe: Option<(&'static str, [u8; 32])>,
        reads: Mutex<Vec<&'static str>>,
    }

    impl ActorFacts for Facts {
        fn uid(&self, _: u32) -> Option<u32> {
            self.reads.lock().push("uid");
            self.uid
        }
        fn cgroup(&self, _: u32) -> Option<String> {
            self.reads.lock().push("cgroup");
            self.cgroup.map(str::to_string)
        }
        fn trusted_exe(&self, _: u32) -> Option<(String, [u8; 32])> {
            self.reads.lock().push("exe");
            self.exe.map(|(p, h)| (p.to_string(), h))
        }
    }

    fn facts() -> Facts {
        Facts {
            uid: Some(998),
            cgroup: Some("/system.slice/backup.service"),
            exe: Some(("/usr/bin/backup", [7u8; 32])),
            reads: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn exemptions_match_their_actor_only() {
        let f = facts();
        let ex = |e: Exemption| exempt(&[e], 42, None, &f);
        assert_eq!(ex(Exemption::Uid(998)).as_deref(), Some("uid 998"));
        assert_eq!(ex(Exemption::Uid(999)), None);
        assert!(ex(Exemption::Unit("backup.service".into())).is_some());
        assert!(ex(Exemption::Unit("other.service".into())).is_none());
        assert!(ex(Exemption::Cgroup("/system.slice/backup.service".into())).is_some());
        assert!(ex(Exemption::Cgroup("/system.slice/other.service".into())).is_none());
        let exe = |path: &str, h: u8| Exemption::Exe {
            path: path.into(),
            sha256: [h; 32],
        };
        assert!(ex(exe("/usr/bin/backup", 7)).is_some());
        // The same path with other content, or the content at another path:
        // not exempt.
        assert!(ex(exe("/usr/bin/backup", 8)).is_none());
        assert!(ex(exe("/usr/bin/other", 7)).is_none());
        // The event's uid wins over /proc.
        assert!(exempt(&[Exemption::Uid(1000)], 42, Some(1000), &f).is_some());
        assert!(exempt(&[Exemption::Uid(998)], 42, Some(1000), &f).is_none());
    }

    /// Fail closed: a fact that cannot be read never exempts; and a
    /// process named like an exempt program is not exempt.
    #[test]
    fn unreadable_facts_never_exempt() {
        let f = Facts {
            uid: None,
            cgroup: None,
            exe: None,
            reads: Mutex::new(Vec::new()),
        };
        for e in [
            Exemption::Uid(998),
            Exemption::Unit("backup.service".into()),
            Exemption::Cgroup("/system.slice/backup.service".into()),
            Exemption::Exe {
                path: "/usr/bin/backup".into(),
                sha256: [7; 32],
            },
        ] {
            assert_eq!(exempt(std::slice::from_ref(&e), 42, None, &f), None, "{e}");
        }
    }

    /// Facts are read only for the kinds present, once each.
    #[test]
    fn facts_are_read_lazily() {
        let f = facts();
        assert_eq!(exempt(&[], 42, None, &f), None);
        assert!(f.reads.lock().is_empty());
        exempt(
            &[
                Exemption::Unit("a.service".into()),
                Exemption::Cgroup("/x/b.service".into()),
                Exemption::Uid(5),
            ],
            42,
            Some(1),
            &f,
        );
        assert_eq!(*f.reads.lock(), vec!["cgroup"]);
    }

    /// The host's own `/proc`: this test process's facts.
    #[test]
    fn proc_facts_read_this_process() {
        let me = std::process::id();
        let f = ProcFacts::default();
        assert_eq!(f.uid(me), Some(unsafe { libc::getuid() }));
        assert!(f.cgroup(me).is_some_and(|c| c.starts_with('/')));
        // A process of an empty /proc has no facts.
        let empty = tempfile::TempDir::new().unwrap();
        let f = ProcFacts::new(empty.path());
        assert_eq!(f.uid(me), None);
        assert_eq!(f.cgroup(me), None);
        assert_eq!(f.trusted_exe(me), None);
    }

    /// A root-owned system binary is trusted with its digest; a file the
    /// test user owns never is.
    #[test]
    fn proc_facts_trust_only_root_owned_system_executables() {
        let dir = tempfile::TempDir::new().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("1")).unwrap();
        let target = Path::new("/bin/sh")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/bin/sh"));
        std::os::unix::fs::symlink(&target, proc_root.join("1/exe")).unwrap();
        let f = ProcFacts::new(&proc_root);
        let (path, digest) = f.trusted_exe(1).expect("a root-owned system shell");
        assert_eq!(Path::new(&path), target);
        assert_eq!(
            digest,
            <[u8; 32]>::from(Sha256::digest(std::fs::read(&target).unwrap()))
        );
        // Cached: the same answer again.
        assert_eq!(f.trusted_exe(1), Some((path, digest)));
        // A file outside the system trees (owned by the test user).
        let mine = dir.path().join("mine");
        std::fs::write(&mine, b"x").unwrap();
        std::fs::create_dir_all(proc_root.join("2")).unwrap();
        std::os::unix::fs::symlink(&mine, proc_root.join("2/exe")).unwrap();
        assert_eq!(f.trusted_exe(2), None);
    }

    #[test]
    fn boot_policy_refuses_a_bad_signed_file_to_the_defaults() {
        let b = boot_policy(Some((
            Path::new("/etc/northnarrow/rule-policy.local"),
            "bogus x\n",
        )));
        assert!(b.policy.is_builtin());
        assert!(b.degraded.as_deref().unwrap().contains("line 1"));
        let b = boot_policy(Some((
            Path::new("/etc/northnarrow/rule-policy.local"),
            "enforce NN-L-IMP-001\n",
        )));
        assert_eq!(b.degraded, None);
        assert_eq!(b.policy.mode(IMP), Some(Mode::Enforce));
        assert!(b.policy.source.contains("(signed, sha256 "));
        let b = boot_policy(None);
        assert!(b.policy.is_builtin());
        assert_eq!(b.policy.source, "built-in defaults");
    }

    #[test]
    fn a_handle_swaps_the_policy() {
        let h = PolicyHandle::default();
        assert!(h.current().is_builtin());
        let held = h.current();
        let old = h.install(parse("enforce NN-L-IMP-001\n").unwrap());
        assert!(old.is_builtin());
        assert_eq!(h.current().mode(IMP), Some(Mode::Enforce));
        // A reader that took the policy before keeps it whole.
        assert!(held.is_builtin());
    }
}
