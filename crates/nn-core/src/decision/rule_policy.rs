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
//! ([`OverlayKind::RulePolicy`](nn_proto::admin_signed_payload::OverlayKind::RulePolicy)):
//! one directive per line, any bad line refuses the whole file
//! ([`parse`]). The engine reads the active policy through a
//! [`PolicyHandle`]; `nn-admin policy set` swaps it between two events.
//! Design: `docs/design/MULTI_MATCH_AND_RULE_POLICY.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
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
    /// The process's cgroup v2 path (a `.service` or `.scope`). Lot 277:
    /// for a process started in it only ([`ActorFacts::started_in_cgroup`]).
    Cgroup(String),
    /// The systemd unit of the process's cgroup (`foo.service`). Lot 277:
    /// for a process started in that cgroup only.
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

/// Lot 275, R6 of the external review of 04/11: the rules `enforce` is
/// refused for, each with why — a match on one attribute that many benign
/// programs share, with no second predicate (a destination, an executable)
/// to act on. In a policy to be signed ([`parse`]: `nn-admin config
/// overlay set`, `policy-test`) the line refuses the file, as any bad line
/// does. In a policy signed before ([`boot_policy`], at the agent's start)
/// only that line is taken as `alert`, the rest in force, and the start
/// signs a degradation naming the line: refusing the whole file would drop
/// its exemptions, its other modes and its switches for one line.
pub const ENFORCE_REFUSED: &[(&str, &str)] = &[
    (
        "NN-L-NET-003_BadJa3",
        "it matches a TLS fingerprint alone, an attribute of the TLS stack that every program on \
         the same library and settings shares, not a program's identity (the fingerprint alone \
         finds 6.82 % of malware, 88.68 % with the destination: Anderson & McGrew); it has no \
         second predicate, a destination or an executable, to act on — `alert` or `audit` it",
    ),
    (
        "NN-L-NET-028_ConnectWithoutDns",
        "it judges the absence of a DNS answer the agent saw, and an answer can be missing for \
         benign reasons it cannot see (a container's resolvers of its own, a client's DNS over \
         TCP, DoT or DoH, an address configured by hand): a kill on it is not fail-safe until it \
         is measured on a wider corpus (review of #495) — `alert` or `audit` it",
    ),
];

/// Why `enforce <id>` is refused, if it is.
pub fn enforce_refused(id: &str) -> Option<&'static str> {
    ENFORCE_REFUSED
        .iter()
        .find(|(r, _)| *r == id)
        .map(|(_, why)| *why)
}

/// A parsed policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulePolicy {
    modes: BTreeMap<&'static str, Mode>,
    exemptions: BTreeMap<&'static str, Vec<Exemption>>,
    /// `combat-without-corroboration NN-L-IMP-001`.
    pub ransomware_combat_without_corroboration: bool,
    /// Lot 280a: `sysctl-allow <name> <value>|<min>..<max>` — the signed
    /// per-sysctl opt-out, by the `sysctl(8)` name of a guarded sysctl
    /// (`common::sysctl_judge::SYSCTL_PATHS`). The agent honours it only
    /// from a policy whose signature it verified.
    sysctl_allow: BTreeMap<&'static str, (i64, i64)>,
    /// Lot 285: `module-allow <module>` — the signed per-module opt-out of
    /// the kernel's module-load judge (a DKMS module built outside a
    /// package transaction, a vendor's module): the files of that module in
    /// the running kernel's tree, owned by root and writable by no one
    /// else, load; every such load is recorded. By the module's name, `-`
    /// read as `_`. The agent honours it only from a policy whose signature
    /// it verified.
    module_allow: std::collections::BTreeSet<String>,
    /// Lot 290: `bpf-loader-allow <executable> <type>[,<type>…]` — the
    /// signed per-loader opt-out of the `bpf` hook's refusal of the program
    /// types that can rewrite user memory, override a kernel function's
    /// return, signal a process or take a hook's place (kprobe, tracing,
    /// lsm, ext, struct_ops): that executable, by the device and inode its
    /// absolute path names when the policy is applied, may load those types
    /// outside a window, each load recorded. The agent honours it only from
    /// a policy whose signature it verified.
    bpf_loader_allow: BTreeMap<String, u32>,
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

    /// Lot 280a: the signed per-sysctl opt-outs — the `sysctl(8)` name,
    /// the guarded sysctl's kind and the values allowed (`min..=max`).
    pub fn sysctl_opt_outs(&self) -> impl Iterator<Item = (&'static str, u8, i64, i64)> + '_ {
        self.sysctl_allow
            .iter()
            .map(|(n, (min, max))| (*n, common::sysctl_judge::kind_of_name(n), *min, *max))
    }

    /// Lot 285: the signed per-module opt-outs, by module name (`_` for
    /// `-`).
    pub fn module_opt_outs(&self) -> impl Iterator<Item = &str> + '_ {
        self.module_allow.iter().map(String::as_str)
    }

    /// Lot 290: the signed per-loader opt-outs — the executable's absolute
    /// path and the mask of the types it may load
    /// (`common::bpf_prog_class::type_bit`).
    pub fn bpf_loader_opt_outs(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.bpf_loader_allow.iter().map(|(p, m)| (p.as_str(), *m))
    }

    /// No directive at all.
    pub fn is_builtin(&self) -> bool {
        self.modes.is_empty()
            && self.exemptions.is_empty()
            && !self.ransomware_combat_without_corroboration
            && self.sysctl_allow.is_empty()
            && self.module_allow.is_empty()
            && self.bpf_loader_allow.is_empty()
    }

    /// One line for the logs and the audit row (lot 280a: the sysctl
    /// opt-outs counted at its end when there are any).
    pub fn summary(&self) -> String {
        let count = |m: Mode| self.modes.values().filter(|x| **x == m).count();
        let mut opt_outs = match self.sysctl_allow.len() {
            0 => String::new(),
            n => format!(", {n} sysctl opt-out{}", if n == 1 { "" } else { "s" }),
        };
        // Lot 285
        match self.module_allow.len() {
            0 => {}
            n => opt_outs.push_str(&format!(
                ", {n} module opt-out{}",
                if n == 1 { "" } else { "s" }
            )),
        }
        // Lot 290
        match self.bpf_loader_allow.len() {
            0 => {}
            n => opt_outs.push_str(&format!(
                ", {n} BPF loader opt-out{}",
                if n == 1 { "" } else { "s" }
            )),
        }
        format!(
            "{} enforce, {} alert, {} audit, {} off, {} exemptions on {} rules, \
             ransomware COMBAT without corroboration {}{opt_outs}",
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
        for (n, (min, max)) in &self.sysctl_allow {
            out.push_str(&format!("sysctl-allow {n} {}\n", range_text(*min, *max)));
        }
        for m in &self.module_allow {
            out.push_str(&format!("module-allow {m}\n"));
        }
        for (path, mask) in &self.bpf_loader_allow {
            out.push_str(&format!(
                "bpf-loader-allow {path} {}\n",
                common::bpf_prog_class::mask_names(*mask)
            ));
        }
        out
    }
}

/// Lot 290: the most `bpf-loader-allow` lines a policy holds (the kernel's
/// map has room for 64 executables).
pub const MAX_BPF_LOADER_OPT_OUTS: usize = 32;

/// Lot 290: a `bpf-loader-allow` line's executable and types — an absolute
/// path without `.` or `..` components, and types among those refused by
/// default (`common::bpf_prog_class::opt_out_type`), each once.
fn bpf_loader_opt_out(path: &str, types: &str) -> Result<(String, u32), String> {
    if !path.starts_with('/')
        || path.len() < 2
        || path.ends_with('/')
        || path
            .split('/')
            .skip(1)
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err("not an absolute path to an executable".to_string());
    }
    let mut mask = 0u32;
    for t in types.split(',') {
        let Some(ty) = common::bpf_prog_class::opt_out_type(t) else {
            return Err(format!(
                "`{t}` is not a type refused by default (kprobe, tracing, lsm, ext, struct_ops)"
            ));
        };
        let bit = common::bpf_prog_class::type_bit(ty);
        if mask & bit != 0 {
            return Err(format!("`{t}` twice"));
        }
        mask |= bit;
    }
    Ok((path.to_string(), mask))
}

/// `v` for one value, `min..max` for a range (the directive's spelling).
fn range_text(min: i64, max: i64) -> String {
    if min == max {
        min.to_string()
    } else {
        format!("{min}..{max}")
    }
}

/// Lot 280a: the value or range of a `sysctl-allow` line — a decimal
/// integer, or two joined by `..` with the first not above the second.
fn parse_range(text: &str) -> Result<(i64, i64), String> {
    let int = |t: &str| {
        t.parse::<i64>()
            .map_err(|_| format!("{t:?}: not a decimal integer"))
    };
    match text.split_once("..") {
        None => int(text).map(|v| (v, v)),
        Some((a, b)) => {
            let (min, max) = (int(a)?, int(b)?);
            if min > max {
                return Err(format!("{text}: the range's first value is above its last"));
            }
            Ok((min, max))
        }
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
        // Lot 280a
        for (n, _, min, max) in p.sysctl_opt_outs() {
            out.push_str(&format!(
                "sysctl-allow {n} {} (outside a window too; honoured only signed)\n",
                range_text(min, max)
            ));
        }
        // Lot 285
        for m in p.module_opt_outs() {
            out.push_str(&format!(
                "module-allow {m} (its files in the running kernel's tree load, each load \
                 recorded; honoured only signed)\n"
            ));
        }
        // Lot 290
        for (path, mask) in p.bpf_loader_opt_outs() {
            out.push_str(&format!(
                "bpf-loader-allow {path} {} (that executable, by its device and inode when the \
                 policy is applied, loads them outside a window, each load recorded; honoured \
                 only signed)\n",
                common::bpf_prog_class::mask_names(mask)
            ));
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

/// The review of #494, N1: the scopes the agent contains processes in
/// (`/northnarrow.slice/blocked.scope`, `throttled.scope`): no exemption
/// names them, by unit either.
const AGENT_CONTAINMENT_UNITS: &[&str] = &["blocked.scope", "throttled.scope"];

/// The review of #494, N1: a cgroup of the agent's containment slice,
/// whose processes the agent moved there; no exemption by cgroup or unit
/// covers them, whatever the policy names.
fn in_containment(cgroup: &str) -> bool {
    cgroup == "/northnarrow.slice" || cgroup.starts_with("/northnarrow.slice/")
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

/// Lot 285: `module-allow` lines a policy may have.
pub const MAX_MODULE_OPT_OUTS: usize = 256;

/// Lot 285: a module name as kmod spells it — letters, digits, `_` and `-`
/// (read as `_`), at most 55 bytes (`MODULE_NAME_LEN` - 1): never a path,
/// a glob or a file name (`.ko`).
pub fn module_opt_out_name(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() > 55 {
        return Err("a module name is 1 to 55 characters".to_string());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(
            "not a module name (letters, digits, `_` and `-` only: no path, no `.ko`, no glob)"
                .to_string(),
        );
    }
    Ok(name.replace('-', "_"))
}

/// Parse a policy file. Any bad line refuses the whole file.
pub fn parse(text: &str) -> Result<RulePolicy, PolicyError> {
    parse_as(text, RefusedEnforce::Refuse).map(|(p, _)| p)
}

/// What [`parse_as`] makes of an `enforce` [`ENFORCE_REFUSED`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusedEnforce {
    /// The line refuses the file (a policy to be signed).
    Refuse,
    /// The line is taken as `alert` and returned (a policy signed before).
    AsAlert,
}

/// An `enforce` line taken as `alert` ([`RefusedEnforce::AsAlert`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemotedEnforce {
    pub line: usize,
    pub rule: &'static str,
    pub why: &'static str,
}

fn parse_as(
    text: &str,
    refused: RefusedEnforce,
) -> Result<(RulePolicy, Vec<DemotedEnforce>), PolicyError> {
    let mut demoted = Vec::new();
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
                let mut mode = Mode::from_keyword(kw).expect("checked");
                let id = resolve_rule(rule).map_err(err)?;
                if mode == Mode::Enforce {
                    if let Some(why) = enforce_refused(id) {
                        if refused == RefusedEnforce::Refuse {
                            return Err(err(format!("enforce {id} is refused: {why}")));
                        }
                        demoted.push(DemotedEnforce {
                            line,
                            rule: id,
                            why,
                        });
                        mode = Mode::Alert;
                    }
                }
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
                        // The review of #494, N1: the agent's containment
                        // scopes hold the processes it contained.
                        if AGENT_CONTAINMENT_UNITS.contains(u) {
                            return Err(err(format!(
                                "unit {u}: the agent's containment scope holds contained processes"
                            )));
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
            // Lot 280a: the signed per-sysctl opt-out
            ["sysctl-allow", name, value] => {
                let kind = common::sysctl_judge::kind_of_name(name);
                if let Err(why) = common::sysctl_judge::opt_out_allowed(kind) {
                    let known: Vec<&str> = common::sysctl_judge::SYSCTL_PATHS
                        .iter()
                        .map(|(_, n, _)| *n)
                        .filter(|n| *n != "kernel.ftrace_enabled")
                        .collect();
                    return Err(err(format!(
                        "sysctl-allow {name}: {why} (one of {})",
                        known.join(", ")
                    )));
                }
                let range =
                    parse_range(value).map_err(|e| err(format!("sysctl-allow {name}: {e}")))?;
                let dotted = common::sysctl_judge::name_of_kind(kind).expect("a guarded kind");
                if p.sysctl_allow.insert(dotted, range).is_some() {
                    return Err(err(format!("sysctl-allow {dotted} twice")));
                }
            }
            ["sysctl-allow", ..] => {
                return Err(err(
                    "`sysctl-allow <sysctl> <value>` or `sysctl-allow <sysctl> <min>..<max>`"
                        .to_string(),
                ))
            }
            // Lot 285: the signed per-module opt-out
            ["module-allow", name] => {
                let m = module_opt_out_name(name)
                    .map_err(|why| err(format!("module-allow {name}: {why}")))?;
                if !p.module_allow.insert(m.clone()) {
                    return Err(err(format!("module-allow {m} twice")));
                }
                if p.module_allow.len() > MAX_MODULE_OPT_OUTS {
                    return Err(err(format!(
                        "more than {MAX_MODULE_OPT_OUTS} module-allow lines"
                    )));
                }
            }
            ["module-allow", ..] => return Err(err("`module-allow <module>`".to_string())),
            // Lot 290: the signed per-loader opt-out of the refused BPF
            // program types
            ["bpf-loader-allow", path, types] => {
                let (path, mask) = bpf_loader_opt_out(path, types)
                    .map_err(|why| err(format!("bpf-loader-allow {path}: {why}")))?;
                if p.bpf_loader_allow.insert(path.clone(), mask).is_some() {
                    return Err(err(format!("bpf-loader-allow {path} twice")));
                }
                if p.bpf_loader_allow.len() > MAX_BPF_LOADER_OPT_OUTS {
                    return Err(err(format!(
                        "more than {MAX_BPF_LOADER_OPT_OUTS} bpf-loader-allow lines"
                    )));
                }
            }
            ["bpf-loader-allow", ..] => {
                return Err(err(
                    "`bpf-loader-allow <absolute executable path> <type>[,<type>…]` (types: \
                     kprobe, tracing, lsm, ext, struct_ops)"
                        .to_string(),
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
                     combat-without-corroboration, sysctl-allow, module-allow, bpf-loader-allow"
                )))
            }
            [] => unreachable!("empty content skipped"),
        }
    }
    Ok((p, demoted))
}

/// The active policy, shared by the engine, the posture and the admin
/// socket. R11c (lab PR 264): the agent's start makes one
/// (`boot::policy::load`, the boot policy in force) and hands a clone to
/// each of them; `nn-admin policy set` installs the next one through the
/// admin socket's clone, and the engine and the posture read it at their
/// next event (it was a process-wide handle, `global()`).
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

/// What the boot read made of the overlay.
#[derive(Debug)]
pub struct BootPolicy {
    pub policy: RulePolicy,
    /// A signed file that did not parse: the built-in defaults are in force.
    pub degraded: Option<String>,
    /// R6 (lot 275): a signed file in force whose `enforce` lines of a rule
    /// [`ENFORCE_REFUSED`] names were taken as `alert`, each named (the
    /// detail of the signed degradation).
    pub demoted: Option<String>,
}

/// The boot policy from the overlay gate's verified text (`None`: absent or
/// refused — the built-in defaults).
pub fn boot_policy(verified: Option<(&Path, &str)>) -> BootPolicy {
    match verified {
        None => BootPolicy {
            policy: RulePolicy::builtin(),
            degraded: None,
            demoted: None,
        },
        Some((path, text)) => match parse_as(text, RefusedEnforce::AsAlert) {
            Ok((mut p, demoted)) => {
                let lines: Vec<String> = demoted
                    .iter()
                    .map(|d| {
                        format!(
                            "line {}: enforce {} refused, applied as alert",
                            d.line, d.rule
                        )
                    })
                    .collect();
                p.source = format!(
                    "{} (signed, sha256 {}{})",
                    path.display(),
                    hex(&Sha256::digest(text.as_bytes())),
                    if lines.is_empty() {
                        String::new()
                    } else {
                        format!("; {}", lines.join("; "))
                    }
                );
                let demoted = (!demoted.is_empty()).then(|| {
                    let each: Vec<String> = demoted
                        .iter()
                        .map(|d| {
                            format!(
                                "line {}: enforce {} refused, applied as alert ({})",
                                d.line, d.rule, d.why
                            )
                        })
                        .collect();
                    format!(
                        "{}: {} — the rest of the policy is in force",
                        path.display(),
                        each.join("; ")
                    )
                });
                BootPolicy {
                    policy: p,
                    degraded: None,
                    demoted,
                }
            }
            Err(e) => BootPolicy {
                policy: RulePolicy::builtin(),
                degraded: Some(format!(
                    "{}: {e} — the built-in defaults are in force",
                    path.display()
                )),
                demoted: None,
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
    /// Lot 277: whether `pid` started in the cgroup it runs in — spawned
    /// into it by systemd, or forked from a process that was — and so may
    /// be exempt by its cgroup or unit. `Some(false)`: it, or a process it
    /// was forked from, was moved into a cgroup (`cgroup.procs`) by anyone
    /// but systemd's placement, or started by `clone3(CLONE_INTO_CGROUP)`
    /// by anyone but PID 1 (the kernel's marks, `nn_linux::cgroup_join`).
    /// `None`: not known (no tracker on this kernel, a mark the kernel
    /// could not take) — not exempt either.
    fn started_in_cgroup(&self, pid: u32) -> Option<bool>;
    /// Lot 281: whether code-injection access to `pid` — or to a process it
    /// was forked from, after that access — was given to another process
    /// (the kernel's marks, `nn_linux::cgroup_join`): an exemption by
    /// executable, cgroup or unit then no longer holds for it. `None`: not
    /// known (no tracker, the process gone or started before the marks'
    /// last reset, a mark the kernel could not take) — no exemption either.
    fn injected(&self, pid: u32) -> Option<Injected>;
}

/// Lot 281: what the kernel's marks say of the code a process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Injected {
    /// No code-injection access to it was ever given, nor to a process it
    /// was forked from after such an access.
    No,
    /// Code-injection access to it was given to pid `by` (a debugger's
    /// attach, a write handle on its memory, ...) — or, `inherited`, to a
    /// process it was forked from (`by` its parent then).
    Yes { by: u32, inherited: bool },
}

/// The outcome of an exemption that matched a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exempt {
    /// The exemption holds: the match is recorded only.
    Holds(String),
    /// Lot 281: the exemption (by executable, cgroup or unit) matched, but
    /// does not hold — code was injected into the process, or that is not
    /// known (`why`): the match is judged as without it.
    Revoked { exemption: String, why: String },
}

impl Exempt {
    /// The exemption, when it holds.
    pub fn holds(&self) -> Option<&str> {
        match self {
            Exempt::Holds(e) => Some(e),
            Exempt::Revoked { .. } => None,
        }
    }
}

/// Lot 281: why an exemption by executable, cgroup or unit does not hold
/// for a process, given what the marks say of its code (`None`: it holds).
pub fn revoked_why(injected: Option<Injected>) -> Option<String> {
    match injected {
        Some(Injected::No) => None,
        Some(Injected::Yes {
            by,
            inherited: false,
        }) => Some(format!(
            "code-injection access to it was given to pid {by} (a debugger's attach, a write \
             handle on its memory, process_vm_writev, pidfd_getfd or PTRACE_TRACEME): revoked for \
             the rest of its life and its children's"
        )),
        Some(Injected::Yes {
            by,
            inherited: true,
        }) => Some(format!(
            "it was forked from a process code-injection access to which had been given (its \
             parent pid {by}): revoked for the rest of its life and its children's"
        )),
        None => Some(
            "whether code was injected into it is not known (no start-in-cgroup tracker, the \
             process gone or started before the marks' last reset, a mark the kernel could not \
             take): an exemption by executable, cgroup or unit holds only for a process known \
             clean"
                .to_string(),
        ),
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
/// present, at most once each. Lot 277: an exemption by cgroup or unit
/// covers a process of that cgroup only if it started there
/// ([`ActorFacts::started_in_cgroup`], read once, and only when a cgroup
/// or a unit matched). Lot 281: an exemption by executable, cgroup or unit
/// that matched holds only for a process no code was injected into
/// ([`ActorFacts::injected`], read once, after the match): else it is
/// [`Exempt::Revoked`] — no other exemption is looked for (the taint voids
/// them all). A uid exemption is the uid's, whatever code runs as it (root
/// can become that uid without injecting anything): not revoked.
pub fn exempt(
    ex: &[Exemption],
    pid: u32,
    event_uid: Option<u32>,
    facts: &dyn ActorFacts,
) -> Option<Exempt> {
    if ex.is_empty() {
        return None;
    }
    let mut uid: Option<Option<u32>> = None;
    let mut cgroup: Option<Option<String>> = None;
    let mut started: Option<Option<bool>> = None;
    let mut exe: Option<Option<(String, [u8; 32])>> = None;
    let mut started_here =
        || *started.get_or_insert_with(|| facts.started_in_cgroup(pid)) == Some(true);
    for e in ex {
        let hit = match e {
            Exemption::Uid(u) => {
                let got = *uid.get_or_insert_with(|| event_uid.or_else(|| facts.uid(pid)));
                got == Some(*u)
            }
            Exemption::Cgroup(c) => {
                cgroup
                    .get_or_insert_with(|| facts.cgroup(pid))
                    .as_deref()
                    .is_some_and(|g| g == c && !in_containment(g))
                    && started_here()
            }
            Exemption::Unit(u) => {
                cgroup
                    .get_or_insert_with(|| facts.cgroup(pid))
                    .as_deref()
                    .filter(|g| !in_containment(g))
                    .and_then(unit_of)
                    .is_some_and(|g| g == u)
                    && started_here()
            }
            Exemption::Exe { path, sha256 } => exe
                .get_or_insert_with(|| facts.trusted_exe(pid))
                .as_ref()
                .is_some_and(|(p, h)| p == path && h == sha256),
        };
        if hit {
            if matches!(e, Exemption::Uid(_)) {
                return Some(Exempt::Holds(e.to_string()));
            }
            return Some(match revoked_why(facts.injected(pid)) {
                None => Exempt::Holds(e.to_string()),
                Some(why) => Exempt::Revoked {
                    exemption: e.to_string(),
                    why,
                },
            });
        }
    }
    None
}

/// Lot 281: the exemption of `policy` (any rule's) that covers process
/// `pid` whatever was injected into it — the agent's question when code
/// was first injected into a process: was it an exempt one? `rule: what`.
pub fn covering(policy: &RulePolicy, pid: u32, facts: &dyn ActorFacts) -> Option<String> {
    struct Clean<'a>(&'a dyn ActorFacts);
    impl ActorFacts for Clean<'_> {
        fn uid(&self, pid: u32) -> Option<u32> {
            self.0.uid(pid)
        }
        fn cgroup(&self, pid: u32) -> Option<String> {
            self.0.cgroup(pid)
        }
        fn trusted_exe(&self, pid: u32) -> Option<(String, [u8; 32])> {
            self.0.trusted_exe(pid)
        }
        fn started_in_cgroup(&self, pid: u32) -> Option<bool> {
            self.0.started_in_cgroup(pid)
        }
        fn injected(&self, _: u32) -> Option<Injected> {
            Some(Injected::No)
        }
    }
    policy.all_exemptions().find_map(|(rule, ex)| {
        exempt(ex, pid, None, &Clean(facts)).and_then(|e| e.holds().map(|e| format!("{rule}: {e}")))
    })
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;
    use crate::posture::host::testing::TestHost as H;

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

    /// Lot 290 (named): the signed per-loader opt-out — an absolute
    /// executable and types refused by default, each once; read back as
    /// written, counted, shown as honoured only signed; a relative path, a
    /// `..`, a type not refused (xdp), a duplicate refused.
    #[test]
    fn a_bpf_loader_opt_out_names_an_executable_and_refused_types() {
        use common::bpf_prog_class::type_bit;
        let p = parse(
            "bpf-loader-allow /usr/bin/bpftrace kprobe,tracing   # the SRE's tracing\n\
             bpf-loader-allow /usr/bin/falco lsm\n",
        )
        .unwrap();
        assert!(!p.is_builtin());
        assert_eq!(
            p.bpf_loader_opt_outs().collect::<Vec<_>>(),
            [
                ("/usr/bin/bpftrace", type_bit(2) | type_bit(26)),
                ("/usr/bin/falco", type_bit(29)),
            ]
        );
        assert_eq!(parse(&p.render()).unwrap(), p);
        assert!(p
            .render()
            .contains("bpf-loader-allow /usr/bin/bpftrace kprobe,tracing\n"));
        assert!(
            p.summary().ends_with(", 2 BPF loader opt-outs"),
            "{}",
            p.summary()
        );
        let shown = show(&p);
        assert!(
            shown.contains("bpf-loader-allow /usr/bin/falco lsm (that executable")
                && shown.contains("honoured only signed"),
            "{shown}"
        );
        for (line, why) in [
            ("bpf-loader-allow bpftrace kprobe\n", "absolute path"),
            (
                "bpf-loader-allow /usr/bin/../tmp/x kprobe\n",
                "absolute path",
            ),
            ("bpf-loader-allow /usr/bin/x/ kprobe\n", "absolute path"),
            (
                "bpf-loader-allow /usr/bin/x xdp\n",
                "not a type refused by default",
            ),
            (
                "bpf-loader-allow /usr/bin/x kprobe,kprobe\n",
                "`kprobe` twice",
            ),
            (
                "bpf-loader-allow /usr/bin/x\n",
                "<absolute executable path>",
            ),
            (
                "bpf-loader-allow /usr/bin/x lsm\nbpf-loader-allow /usr/bin/x ext\n",
                "/usr/bin/x twice",
            ),
        ] {
            let e = parse(line).unwrap_err().to_string();
            assert!(e.contains(why), "{line:?}: {e}");
        }
        let many: String = (0..=MAX_BPF_LOADER_OPT_OUTS)
            .map(|i| format!("bpf-loader-allow /opt/t{i} kprobe\n"))
            .collect();
        assert!(parse(&many).unwrap_err().to_string().contains("more than"));
    }

    /// Lot 280a: the signed per-sysctl opt-out — a guarded sysctl by its
    /// `sysctl(8)` name and a value or a range; read back as written,
    /// counted, shown; never kernel.ftrace_enabled, never another sysctl,
    /// one line per sysctl, a range in order.
    #[test]
    fn a_sysctl_opt_out_names_a_guarded_sysctl_and_its_values() {
        use common::cgroup_limits::{SYSCTL_PID_MAX, SYSCTL_SCHED_RT_RUNTIME};
        let p = parse(
            "sysctl-allow kernel.sched_rt_runtime_us -1   # tuned realtime\n\
             sysctl-allow kernel.pid_max 4096..32767\n",
        )
        .unwrap();
        assert!(!p.is_builtin());
        let got: Vec<_> = p.sysctl_opt_outs().collect();
        assert_eq!(
            got,
            [
                ("kernel.pid_max", SYSCTL_PID_MAX, 4096, 32767),
                (
                    "kernel.sched_rt_runtime_us",
                    SYSCTL_SCHED_RT_RUNTIME,
                    -1,
                    -1
                ),
            ]
        );
        assert_eq!(parse(&p.render()).unwrap(), p);
        assert!(p
            .render()
            .contains("sysctl-allow kernel.sched_rt_runtime_us -1\n"));
        assert!(p
            .render()
            .contains("sysctl-allow kernel.pid_max 4096..32767\n"));
        assert!(
            p.summary().ends_with(", 2 sysctl opt-outs"),
            "{}",
            p.summary()
        );
        // a range of one value is that value
        let one = parse("sysctl-allow kernel.pid_max 4096..4096\n").unwrap();
        assert_eq!(
            one.sysctl_opt_outs().collect::<Vec<_>>(),
            [("kernel.pid_max", SYSCTL_PID_MAX, 4096, 4096)]
        );
        assert_eq!(one.render(), "sysctl-allow kernel.pid_max 4096\n");
        assert!(parse("sysctl-allow kernel.pid_max 4096\n")
            .unwrap()
            .summary()
            .ends_with(", 1 sysctl opt-out"));
        // without one, the summary is the one before lot 280a
        assert!(parse("enforce R020\n")
            .unwrap()
            .summary()
            .ends_with("ransomware COMBAT without corroboration off"));
        let shown = show(&p);
        assert!(
            shown.contains("sysctl-allow kernel.sched_rt_runtime_us -1 (outside a window too; honoured only signed)"),
            "{shown}"
        );
        for (text, what) in [
            ("sysctl-allow kernel.ftrace_enabled 1\n", "never opted out"),
            (
                "sysctl-allow kernel.printk 4\n",
                "not a sysctl the agent guards",
            ),
            (
                "sysctl-allow kernel/pid_max 4096\n",
                "not a sysctl the agent guards",
            ),
            (
                "sysctl-allow pid_max 4096\n",
                "not a sysctl the agent guards",
            ),
            (
                "sysctl-allow kernel.pid_max\n",
                "sysctl-allow <sysctl> <value>",
            ),
            (
                "sysctl-allow kernel.pid_max 1 2\n",
                "sysctl-allow <sysctl> <value>",
            ),
            (
                "sysctl-allow kernel.pid_max 0x1000\n",
                "not a decimal integer",
            ),
            ("sysctl-allow kernel.pid_max 9..1\n", "above its last"),
            ("sysctl-allow kernel.pid_max 1..\n", "not a decimal integer"),
            (
                "sysctl-allow kernel.pid_max 1\nsysctl-allow kernel.pid_max 2\n",
                "twice",
            ),
        ] {
            let e = refused(text);
            assert!(e.why.contains(what), "{text:?}: {e}");
        }
        assert!(refused("sysctl-allow kernel.printk 4\n")
            .why
            .contains("kernel.sched_rt_runtime_us"));
        assert!(!refused("sysctl-allow kernel.printk 4\n")
            .why
            .contains("kernel.ftrace_enabled,"));
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
            ("exempt R020 unit blocked.scope\n", 1, "containment scope"),
            ("exempt R020 unit throttled.scope\n", 1, "containment scope"),
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
            // R6 (lot 275): a fingerprint alone is not an identity
            ("enforce NN-L-NET-003\n", 1, "enforce NN-L-NET-003_BadJa3 is refused"),
            (
                "alert R020\nenforce NN-L-NET-003_BadJa3\n",
                2,
                "no second predicate",
            ),
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
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(proc.path());
        let engine = crate::decision::replay::engine(crate::decision::replay::HostParts {
            configs: Path::new(concat!(env!("NN_REPO_ROOT"), "/configs")),
            proc_root: proc.path(),
            lineage: lineage.clone(),
            ransom: Arc::new(crate::impact::RansomTracker::<H>::new(lineage)),
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
        /// Lot 277.
        started: Option<bool>,
        /// Lot 281.
        injected: Option<Injected>,
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
        fn started_in_cgroup(&self, _: u32) -> Option<bool> {
            self.reads.lock().push("started");
            self.started
        }
        fn injected(&self, _: u32) -> Option<Injected> {
            self.reads.lock().push("injected");
            self.injected
        }
    }

    fn facts() -> Facts {
        Facts {
            uid: Some(998),
            cgroup: Some("/system.slice/backup.service"),
            exe: Some(("/usr/bin/backup", [7u8; 32])),
            started: Some(true),
            injected: Some(Injected::No),
            reads: Mutex::new(Vec::new()),
        }
    }

    /// The review of #494, N1: a process of the agent's containment slice is
    /// never exempt by cgroup or unit — a unit name below it (a NEUTRALIZE
    /// cgroup's `x.scope`) included; its uid exemption still holds.
    #[test]
    fn a_contained_process_is_never_exempt_by_cgroup_or_unit() {
        let contained = Facts {
            cgroup: Some("/northnarrow.slice/blocked.scope/backup.service"),
            ..facts()
        };
        assert_eq!(
            exempt(
                &[Exemption::Unit("backup.service".into())],
                42,
                None,
                &contained
            ),
            None
        );
        assert_eq!(
            exempt(
                &[Exemption::Cgroup(
                    "/northnarrow.slice/blocked.scope/backup.service".into()
                )],
                42,
                None,
                &contained
            ),
            None
        );
        assert!(exempt(&[Exemption::Uid(998)], 42, None, &contained).is_some());
        assert!(in_containment("/northnarrow.slice"));
        assert!(!in_containment("/northnarrow.slicex/a.service"));
    }

    /// Lot 277: an exemption by cgroup or unit holds for a process started
    /// in the cgroup only — not for one moved into it (or forked from one
    /// that was), nor where that is not known; the other kinds do not ask.
    #[test]
    fn a_cgroup_or_unit_exemption_needs_a_start_in_the_cgroup() {
        for (started, holds) in [(Some(true), true), (Some(false), false), (None, false)] {
            let f = Facts { started, ..facts() };
            for e in [
                Exemption::Unit("backup.service".into()),
                Exemption::Cgroup("/system.slice/backup.service".into()),
            ] {
                assert_eq!(
                    exempt(std::slice::from_ref(&e), 42, None, &f).is_some(),
                    holds,
                    "{e} with started {started:?}"
                );
            }
            // a uid or exe exemption is the actor's, wherever it started
            assert!(exempt(&[Exemption::Uid(998)], 42, None, &f).is_some());
            assert!(exempt(
                &[Exemption::Exe {
                    path: "/usr/bin/backup".into(),
                    sha256: [7; 32],
                }],
                42,
                None,
                &f
            )
            .is_some());
        }
        // a moved process exempt by its uid still is, and says so
        let moved = Facts {
            started: Some(false),
            ..facts()
        };
        assert_eq!(
            exempt(
                &[
                    Exemption::Unit("backup.service".into()),
                    Exemption::Uid(998)
                ],
                42,
                None,
                &moved
            )
            .as_ref()
            .and_then(Exempt::holds),
            Some("uid 998")
        );
        // the start is read once, after a cgroup matched, never before
        let f = facts();
        exempt(
            &[
                Exemption::Unit("other.service".into()),
                Exemption::Cgroup("/x/b.service".into()),
            ],
            42,
            None,
            &f,
        );
        assert_eq!(*f.reads.lock(), vec!["cgroup"]);
        let f = Facts {
            started: Some(false),
            ..facts()
        };
        exempt(
            &[
                Exemption::Unit("backup.service".into()),
                Exemption::Cgroup("/system.slice/backup.service".into()),
            ],
            42,
            None,
            &f,
        );
        assert_eq!(*f.reads.lock(), vec!["cgroup", "started"]);
    }

    #[test]
    fn exemptions_match_their_actor_only() {
        let f = facts();
        let ex = |e: Exemption| exempt(&[e], 42, None, &f);
        assert_eq!(
            ex(Exemption::Uid(998)).as_ref().and_then(Exempt::holds),
            Some("uid 998")
        );
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
            started: None,
            injected: None,
            reads: Mutex::new(Vec::new()),
        };
        for (case, e) in [
            Exemption::Uid(998),
            Exemption::Unit("backup.service".into()),
            Exemption::Cgroup("/system.slice/backup.service".into()),
            Exemption::Exe {
                path: "/usr/bin/backup".into(),
                sha256: [7; 32],
            },
        ]
        .iter()
        .enumerate()
        {
            assert!(
                exempt(std::slice::from_ref(e), 42, None, &f).is_none(),
                "case {case}"
            );
        }
    }

    /// Lot 281 (named): an exemption by executable, cgroup or unit that
    /// matched does not hold for a process code was injected into — nor
    /// for one forked from it, nor where that is not known — and says why;
    /// a uid exemption is the uid's and holds; the marks are read once,
    /// after a match only; `covering` names the exemption whatever was
    /// injected (the agent's question at the injection).
    #[test]
    fn an_exemption_is_revoked_once_code_was_injected() {
        let exe = Exemption::Exe {
            path: "/usr/bin/backup".into(),
            sha256: [7; 32],
        };
        let kinds = [
            exe.clone(),
            Exemption::Unit("backup.service".into()),
            Exemption::Cgroup("/system.slice/backup.service".into()),
        ];
        for (injected, needle) in [
            (
                Some(Injected::Yes {
                    by: 4242,
                    inherited: false,
                }),
                "given to pid 4242",
            ),
            (
                Some(Injected::Yes {
                    by: 77,
                    inherited: true,
                }),
                "parent pid 77",
            ),
            (None, "not known"),
        ] {
            let f = Facts {
                injected,
                ..facts()
            };
            for (case, e) in kinds.iter().enumerate() {
                match exempt(std::slice::from_ref(e), 42, None, &f) {
                    Some(Exempt::Revoked { exemption, why }) => {
                        assert!(exemption == e.to_string(), "case {case}");
                        assert!(why.contains(needle), "case {case}: {needle}");
                    }
                    other => panic!("case {case}: revoked expected, found {}", other.is_some()),
                }
            }
            // the uid's exemption holds, whatever runs as it
            assert_eq!(
                exempt(&[Exemption::Uid(998)], 42, None, &f),
                Some(Exempt::Holds("uid 998".into()))
            );
            // the taint voids them all: the first match answers
            assert!(matches!(
                exempt(&[exe.clone(), Exemption::Uid(998)], 42, None, &f),
                Some(Exempt::Revoked { .. })
            ));
        }
        // a clean process keeps its exemptions
        let f = facts();
        for e in &kinds {
            assert_eq!(
                exempt(std::slice::from_ref(e), 42, None, &f),
                Some(Exempt::Holds(e.to_string()))
            );
        }
        // read once, after the match, never for a miss or a uid
        let f = facts();
        exempt(
            &[
                Exemption::Exe {
                    path: "/usr/bin/other".into(),
                    sha256: [7; 32],
                },
                Exemption::Uid(5),
            ],
            42,
            None,
            &f,
        );
        assert_eq!(*f.reads.lock(), vec!["exe", "uid"]);
        let f = facts();
        exempt(&[Exemption::Uid(998)], 42, None, &f);
        assert_eq!(*f.reads.lock(), vec!["uid"]);
        let f = facts();
        exempt(&kinds[1..], 42, None, &f);
        assert_eq!(*f.reads.lock(), vec!["cgroup", "started", "injected"]);
        // the agent's question at the injection: the exemption, whatever
        // the marks say now
        let p = parse(
            "exempt R017 uid 1\n\
             exempt NN-L-IMP-001 exe /usr/bin/backup sha256 0707070707070707070707070707070707070707070707070707070707070707\n",
        )
        .unwrap();
        let tainted = Facts {
            injected: Some(Injected::Yes {
                by: 1,
                inherited: false,
            }),
            ..facts()
        };
        let got = covering(&p, 42, &tainted).expect("an exemption covered it");
        assert!(
            got.starts_with("NN-L-IMP-001_RansomwareEncryption: exe /usr/bin/backup"),
            "{got}"
        );
        assert!(!tainted.reads.lock().contains(&"injected"));
        let nobody = Facts {
            exe: None,
            uid: Some(5),
            ..facts()
        };
        assert_eq!(covering(&p, 42, &nobody), None);
        assert_eq!(covering(&RulePolicy::builtin(), 42, &tainted), None);
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

    /// R6 (lot 275): a policy to be signed that enforces NN-L-NET-003 is
    /// refused whole (above, `every_bad_line_refuses_the_file_with_its_number`);
    /// one signed before keeps every other line at the start — its
    /// exemptions, its other modes, its switch — and that line is taken as
    /// `alert`, named in the degradation the start signs. Every other mode
    /// of the rule is accepted, and `enforce` of another rule still is.
    #[test]
    fn a_signed_enforce_of_a_fingerprint_rule_is_applied_as_alert_at_the_start() {
        const NET_003: &str = "NN-L-NET-003_BadJa3";
        let text = "off R008\nexempt R020 uid 998\nenforce NN-L-NET-003\nenforce NN-L-IMP-001\n\
                    combat-without-corroboration NN-L-IMP-001\n";
        assert!(parse(text).is_err(), "to be signed: refused whole");
        let b = boot_policy(Some((
            Path::new("/etc/northnarrow/rule-policy.local"),
            text,
        )));
        assert_eq!(b.degraded, None, "not the defaults");
        assert!(!b.policy.is_builtin());
        // the other lines in force
        assert_eq!(
            b.policy.mode(resolve_rule("R008").unwrap()),
            Some(Mode::Off)
        );
        assert_eq!(b.policy.mode(IMP), Some(Mode::Enforce));
        assert_eq!(
            b.policy.exemptions(resolve_rule("R020").unwrap()),
            &[Exemption::Uid(998)][..]
        );
        assert!(b.policy.ransomware_combat_without_corroboration);
        // that line as alert, named
        assert_eq!(b.policy.mode(NET_003), Some(Mode::Alert));
        let d = b.demoted.expect("a signed degradation");
        assert!(
            d.contains("line 3: enforce NN-L-NET-003_BadJa3 refused, applied as alert")
                && d.contains("no second predicate")
                && d.contains("the rest of the policy is in force"),
            "{d}"
        );
        assert!(
            b.policy
                .source
                .contains("line 3: enforce NN-L-NET-003_BadJa3 refused, applied as alert"),
            "{}",
            b.policy.source
        );
        // a policy without such a line: nothing demoted
        let b = boot_policy(Some((
            Path::new("/etc/northnarrow/rule-policy.local"),
            "enforce NN-L-IMP-001\n",
        )));
        assert_eq!((b.degraded, b.demoted), (None, None));
        // a line the start cannot read still refuses the file to the defaults
        let b = boot_policy(Some((
            Path::new("/etc/northnarrow/rule-policy.local"),
            "enforce NN-L-NET-003\nbogus x\n",
        )));
        assert!(b.policy.is_builtin() && b.demoted.is_none());
        assert!(b.degraded.unwrap().contains("line 2"));
        for mode in ["alert", "audit", "off"] {
            let p = parse(&format!("{mode} NN-L-NET-003\n")).unwrap();
            assert_eq!(p.mode(NET_003).map(Mode::keyword), Some(mode), "{mode}");
        }
        assert!(parse("exempt NN-L-NET-003 uid 1000\n").is_ok());
        assert!(parse("enforce NN-L-IMP-001\n").is_ok());
        // review of #495: NN-L-NET-028's kill is not fail-safe either
        assert!(parse("enforce NN-L-NET-028\n").is_err());
        let b = boot_policy(Some((
            Path::new("/etc/northnarrow/rule-policy.local"),
            "enforce NN-L-NET-028\noff R008\n",
        )));
        assert_eq!(
            b.policy.mode("NN-L-NET-028_ConnectWithoutDns"),
            Some(Mode::Alert)
        );
        assert_eq!(
            b.policy.mode(resolve_rule("R008").unwrap()),
            Some(Mode::Off)
        );
        assert!(b
            .demoted
            .unwrap()
            .contains("line 1: enforce NN-L-NET-028_ConnectWithoutDns refused, applied as alert"));
        assert_eq!(
            ENFORCE_REFUSED.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            vec![NET_003, "NN-L-NET-028_ConnectWithoutDns"]
        );
        // every refused id is a rule the policy knows
        for (id, why) in ENFORCE_REFUSED {
            assert_eq!(resolve_rule(id), Ok(*id));
            assert!(!why.is_empty());
        }
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

    /// Named test (lot 285, the policy's half): `module-allow <module>` names
    /// a module (`-` read as `_`), read back as written, counted and shown;
    /// never a path, a file name or a glob, never twice.
    #[test]
    fn a_signed_per_module_opt_out_names_a_module() {
        let p = parse("module-allow nvidia-drm\nmodule-allow vboxdrv   # VirtualBox\n").unwrap();
        assert!(!p.is_builtin());
        assert_eq!(
            p.module_opt_outs().collect::<Vec<_>>(),
            ["nvidia_drm", "vboxdrv"]
        );
        assert_eq!(parse(&p.render()).unwrap(), p);
        assert!(p.render().contains("module-allow nvidia_drm\n"));
        assert!(
            p.summary().ends_with(", 2 module opt-outs"),
            "{}",
            p.summary()
        );
        assert!(
            show(&p).contains("module-allow vboxdrv (its files"),
            "{}",
            show(&p)
        );
        for (text, what) in [
            ("module-allow /tmp/rk.ko\n", "not a module name"),
            ("module-allow rk.ko\n", "not a module name"),
            ("module-allow nv*\n", "not a module name"),
            ("module-allow\n", "`module-allow <module>`"),
            ("module-allow a b\n", "`module-allow <module>`"),
            (
                "module-allow nvidia_drm\nmodule-allow nvidia-drm\n",
                "twice",
            ),
        ] {
            let e = parse(text).unwrap_err().to_string();
            assert!(e.contains(what), "{text:?}: {e}");
        }
        let long = "m".repeat(56);
        assert!(parse(&format!("module-allow {long}\n")).is_err());
        let many: String = (0..=MAX_MODULE_OPT_OUTS)
            .map(|i| format!("module-allow m{i}\n"))
            .collect();
        assert!(parse(&many)
            .unwrap_err()
            .to_string()
            .contains("module-allow lines"));
    }
}
