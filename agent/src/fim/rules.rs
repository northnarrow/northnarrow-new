//! Tappa 9 (C5) — File Integrity Monitoring (FIM) detection
//! rules NN-L-FIM-001..009.
//!
//! Nine rules matching the §7 design table. Each implements the
//! existing [`crate::decision::Rule`] trait and inspects only
//! [`Event::Fim`] variants — non-FIM events return `None`
//! early. The engine evaluates the FIM rules alongside the
//! existing R001..R012 rules; the rule that fires picks the
//! response action + severity, which the agent's existing
//! posture state machine + response executor consume
//! unchanged.
//!
//! ## §13 Q4 + §7 footer lock-ins reflected here
//!
//! - **NN-L-FIM-001, NN-L-FIM-002, NN-L-FIM-008 are Critical**
//!   (KillProcessTree + posture transition to COMBAT in
//!   `agent/src/main.rs::process_event`). The C4 rate-limiter
//!   never throttles Critical events — these rules fire for
//!   every kernel-observed match.
//! - **NN-L-FIM-002 hardlink semantics** (§13 Q2 lock-in): a
//!   Linked op whose destination is in a user-writable directory
//!   (`/tmp/`, `/var/tmp/`, `/dev/shm/`, `/home/`) is Critical — the
//!   kernel reports a link only when its SOURCE inode is watched, so
//!   that is a watched binary given a second name. A Created op there
//!   is recorded (Medium, external audit FIMR-006). Mirrors the C4
//!   `DriftClassifier::classify` Critical arm so the rule + classifier
//!   agree.
//! - **NN-L-FIM-005 log-truncation** is High but log-only
//!   (no kill) — operators legitimately truncate logs;
//!   killing the modifier (often `logrotate`) is the wrong
//!   response. The audit chain captures the event regardless.
//!
//! ## Operator-tunable false-positive guards
//!
//! Every path-prefix rule maintains a `*_WHITELIST` const slot
//! the operator can extend without touching rule bodies. For
//! example NN-L-FIM-006 (operator-installed binaries) often
//! sees legitimate updates from operator package managers;
//! the whitelist exempts well-known signed-update tools by
//! comm.

use std::collections::VecDeque;
use std::sync::Arc;

use common::wire::{FimEvent, FimOp, InodeKey};
use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::anti_tamper::trusted_installer::{TrustedInstallerOverride, OWN_SYSTEMD_UNITS};
use crate::decision::Rule;
use crate::posture::lineage::AuthSessionTracker;

// ── shared path-prefix sets ────────────────────────────────────────

/// §13 Q2 user-writable directory prefixes — the destination
/// of a hardlink that lands here gets Critical severity in
/// NN-L-FIM-002, mirroring `DriftClassifier::classify`.
const USER_WRITABLE_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/home/"];

/// NN-L-FIM-001: system-binary paths. Any Modified-op drift
/// against these is Critical (T1485-ish persistence /
/// supply-chain tamper).
const SYSTEM_BINARY_PREFIXES: &[&str] =
    &["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/"];

/// NN-L-FIM-003: sensitive on-disk config exact paths. Modifications
/// are High; the audit chain captures the modifier triple so the
/// operator can correlate with package-manager activity.
const SENSITIVE_CONFIG_EXACT: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
];

/// NN-L-FIM-005: log file roots. The rule's name is "log
/// truncated" but in C5 we trigger on any Modified op against
/// these paths whose `new_sha256` differs from baseline AND
/// the file shrunk (size-decrease check happens via the
/// baseline + new size; if either is unknown we err on the
/// side of alerting).
const LOG_ROOT_PREFIXES: &[&str] = &["/var/log/", "/var/audit/"];

/// NN-L-FIM-005 false-positive guard: kernel-resolved exec paths of
/// the rsyslog daemon. A `Modified` op on a [`LOG_ROOT_PREFIXES`] path
/// whose writer `/proc/<pid>/exe` is one of these — AND running as the
/// `syslog` user — AND growing the file (an append) is rsyslogd's own
/// routine logging, not tampering, so it is exempted. `/sbin` and
/// `/usr/sbin` are BOTH listed because merged-`/usr` systems symlink
/// one to the other and `/proc/<pid>/exe` reports whichever is the
/// canonical target; an exact-path match (never `comm`) keeps the
/// exemption tight. A truncation (file shrank) by this same daemon is
/// NOT exempted — it still fires (log-tamper indicator). Sorted.
const RSYSLOGD_EXES: &[&str] = &["/sbin/rsyslogd", "/usr/sbin/rsyslogd"];

/// NN-L-FIM-006: operator-installed binary roots. Modifications
/// here are Medium (often legit package upgrades), but worth
/// surfacing so an unexpected one stands out.
const OPERATOR_BIN_PREFIXES: &[&str] = &["/usr/local/bin/", "/usr/local/sbin/", "/opt/"];

/// NN-L-FIM-007: cron drop-in roots. Created op against any of
/// these is High — a new cron entry is the canonical
/// persistence mechanism (MITRE T1053 Scheduled Task/Job).
const CRON_DROPIN_PATHS: &[&str] = &[
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
    "/etc/crontab",
];

/// NN-L-FIM-008: kernel module file roots. Critical — a
/// modified kmod is a rootkit-class compromise.
const KMOD_PREFIX: &str = "/lib/modules/";

/// NN-L-FIM-009: systemd unit file roots. Created or Modified
/// op is High — drop-in unit persistence (MITRE T1543.002).
const SYSTEMD_UNIT_PREFIXES: &[&str] = &[
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
];

// ── helpers ────────────────────────────────────────────────────────

/// Extract the inner `FimEvent` ref from an `Event` or return
/// `None`. All FIM rules call this first.
fn as_fim(e: &Event) -> Option<&FimEvent> {
    match e {
        Event::Fim(fe) => Some(fe),
        _ => None,
    }
}

/// Q8, decided 2026-10-12: a credential file read by a non-root user
/// other than its owner. Not root's read (backups read every home), nor a
/// reader that reads as root does (a backup tool given
/// CAP_DAC_READ_SEARCH), nor a read whose owner is unknown.
fn is_foreign_read(fe: &FimEvent) -> bool {
    fe.owner_uid.is_some_and(|owner| {
        fe.modifier_uid != 0 && fe.modifier_uid != owner && !fe.reader_dac_capable
    })
}

/// Build a Verdict from a FimEvent. The agent's existing
/// `decision::rules::build_verdict` extracts ProcessSpawn
/// fields — we duplicate the shape here for FimEvent so the
/// existing `build_verdict` stays focused on process events
/// (avoids growing an `event` -> conditional-field-extraction
/// match in shared code that already has 6+ Event arms).
fn fim_verdict(
    rule: &dyn Rule,
    fe: &FimEvent,
    action: ResponseAction,
    severity: Severity,
    reasoning: &str,
) -> Verdict {
    // Tappa 10.9 step 1: opens found by the file-open sensor's credential
    // names (every home) are reported: the owner's own editor or SDK opens
    // them too. Q8: another user's read is acted on ([`is_foreign_read`]).
    let foreign = is_foreign_read(fe);
    let (action, reasoning) = if fe.wide_coverage && !foreign {
        (ResponseAction::Log, reasoning.to_string())
    } else if foreign {
        (
            action,
            format!(
                "{reasoning} [uid {} read a file owned by uid {}]",
                fe.modifier_uid,
                fe.owner_uid.unwrap_or_default()
            ),
        )
    } else {
        (action, reasoning.to_string())
    };
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity,
        reasoning,
        event_pid: fe.modifier_pid,
        event_filename: fe.path.clone(),
        timestamp_ns: fe.timestamp_ns,
    }
}

fn starts_with_any(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

fn is_user_writable(path: &str) -> bool {
    starts_with_any(path, USER_WRITABLE_PREFIXES)
}

/// Resolve a local system user's uid by parsing `/etc/passwd` once.
/// Std-only — no NSS/FFI — which is exactly right for the `syslog`
/// user NN-L-FIM-005 needs: it is always a local account installed by
/// the rsyslog package, never an LDAP/NSS-only identity. Returns `None`
/// if the file is unreadable or the user is absent (caller treats that
/// as "carve-out disabled"). Called once at engine construction, not on
/// the event hot path.
fn resolve_uid_by_name(name: &str) -> Option<u32> {
    let body = std::fs::read_to_string("/etc/passwd").ok()?;
    parse_passwd_uid(&body, name)
}

/// Pure parser behind [`resolve_uid_by_name`] — find `name`'s uid
/// (colon field 3, 0-indexed 2) in a `/etc/passwd` body. Split out so
/// the parse is unit-testable without touching the real file. Ignores
/// blank/comment lines and malformed rows; first match wins.
fn parse_passwd_uid(passwd_body: &str, name: &str) -> Option<u32> {
    for line in passwd_body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // name:passwd:uid:gid:gecos:home:shell
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        // Skip the password field, then take uid.
        return fields.nth(1).and_then(|uid| uid.parse().ok());
    }
    None
}

// ── NN-L-FIM-001 — system binary modified ──────────────────────────

/// Modification of any file under `/bin/`, `/sbin/`, `/usr/bin/`,
/// `/usr/sbin/`, or `/usr/lib/`. Critical (system-binary
/// tamper = supply-chain compromise class). Action:
/// KillProcessTree of the modifier. Posture transition handled
/// by the agent's posture state machine on Critical severity.
pub struct NnLFim001SystemBinaryModified;

impl Rule for NnLFim001SystemBinaryModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-001_SystemBinaryModified"
    }
    fn name(&self) -> &'static str {
        "System binary modified"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        // Wave 2 (TST-004): a permission or ownership change that hands out
        // power over the binary (a set-id bit, write for group or others, a
        // new owner) is the same foothold as a rewrite. One that only takes
        // power away (`chmod u-s`, a hardening step) is recorded, not
        // killed.
        let reasoning = match fe.op {
            FimOp::Modified => {
                "System binary modified — supply-chain / persistence indicator".to_string()
            }
            FimOp::AttrChanged => {
                let attrs = fe.attrs.filter(|a| a.grants_privilege())?;
                format!(
                    "System binary permissions changed: {} — privilege-escalation / \
                     persistence indicator",
                    attrs.describe()
                )
            }
            _ => return None,
        };
        if !starts_with_any(&fe.path, SYSTEM_BINARY_PREFIXES) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            &reasoning,
        ))
    }
}

// ── NN-L-FIM-002 — new SUID-root binary appeared ───────────────────

/// `Linked` op whose destination is in a user-writable directory: a
/// watched inode (`inode_link` reports a link only when its source is
/// watched — a SUID-root system binary) given a name where an
/// unprivileged user controls it, the §13 Q2 hardlink-evasion path.
/// Critical, the process tree killed.
///
/// External audit FIMR-006: a `Created` op there is recorded, not killed.
/// It comes from the hook on the watched DIRECTORY, and the shipped
/// `fim-paths.v1` tells operators to watch `/home/<user>/…` profile paths:
/// every temporary file a browser, GnuPG or an SDK wrote there killed its
/// process tree and put the host in COMBAT. The kernel hook carries no mode
/// bits, so a new SUID file cannot be told from any other file here; a
/// SUID bit set afterwards is a `chmod` — Modified, NN-L-FIM-001's and the
/// capability rules' ground.
pub struct NnLFim002NewSuidBinary;

impl Rule for NnLFim002NewSuidBinary {
    fn id(&self) -> &'static str {
        "NN-L-FIM-002_NewSuidBinary"
    }
    fn name(&self) -> &'static str {
        "New SUID-root binary appeared in user-writable dir"
    }
    fn category(&self) -> &'static str {
        "fim_evasion"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Created | FimOp::Linked) {
            return None;
        }
        if !is_user_writable(&fe.path) {
            return None;
        }
        if fe.op == FimOp::Created {
            return Some(fim_verdict(
                self,
                fe,
                ResponseAction::Log,
                Severity::Medium,
                "File created in a watched user-writable directory — recorded (a \
                 hardlink of a watched binary is the kill case, §13 Q2)",
            ));
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "Watched inode hardlinked into a user-writable dir — SUID evasion path \
             (§13 Q2)",
        ))
    }
}

// ── NN-L-FIM-003 — sensitive config modified ───────────────────────

/// Modification of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
/// `/etc/ssh/sshd_config`, or the relevant `/etc/pam.d/`
/// entries. High severity (any legitimate user-management
/// operation goes through these paths — operator wants to know
/// even when the change is sanctioned).
pub struct NnLFim003SensitiveConfigModified;

impl Rule for NnLFim003SensitiveConfigModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-003_SensitiveConfigModified"
    }
    fn name(&self) -> &'static str {
        "Sensitive config modified"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        // Wave 2 (TST-004): `chmod o+r /etc/shadow` exposes every hash
        // without touching a byte; a new owner can rewrite the file later.
        let reasoning = match fe.op {
            FimOp::Modified => "Sensitive system config modified".to_string(),
            FimOp::AttrChanged => {
                let attrs = fe
                    .attrs
                    .filter(|a| a.grants_privilege() || a.exposes_content())?;
                format!(
                    "Sensitive system config permissions changed: {}",
                    attrs.describe()
                )
            }
            _ => return None,
        };
        if !SENSITIVE_CONFIG_EXACT.iter().any(|p| fe.path == *p) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcess,
            Severity::High,
            &reasoning,
        ))
    }
}

// ── NN-L-FIM-004 — authorized_keys modified ────────────────────────

/// Modification of any `.ssh/authorized_keys` file (root's,
/// per-user). High severity — this is the canonical SSH
/// backdoor persistence mechanism (MITRE T1098.004).
pub struct NnLFim004AuthorizedKeysModified;

impl Rule for NnLFim004AuthorizedKeysModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-004_AuthorizedKeysModified"
    }
    fn name(&self) -> &'static str {
        "SSH authorized_keys modified"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        // Wave 2 (TST-004): a key file handed to another owner, or made
        // writable by group or others, is ready for someone else's key.
        match fe.op {
            // A key file that appears in a watched directory is a new
            // key as much as an edited one is.
            FimOp::Modified | FimOp::Created => {}
            FimOp::AttrChanged if fe.attrs.is_some_and(|a| a.grants_privilege()) => {}
            _ => return None,
        }
        // External audit FIMR-007: sshd reads `.ssh/authorized_keys2` too
        // — its built-in `AuthorizedKeysFile` is `.ssh/authorized_keys
        // .ssh/authorized_keys2`, which Debian and Ubuntu leave in place —
        // and the shipped watch list covers `/etc/ssh/authorized_keys`.
        // Whole-component matches, so `authorized_keys2.bak` or a directory
        // whose name merely contains the string do not match.
        if !is_authorized_keys_path(&fe.path) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcess,
            Severity::High,
            "SSH authorized_keys modified — backdoor persistence indicator",
        ))
    }
}

/// A file sshd reads public keys from: `~/.ssh/authorized_keys`,
/// `~/.ssh/authorized_keys2`, `/etc/ssh/authorized_keys`, or one under
/// `/etc/ssh/authorized_keys/` (the `%u` form).
fn is_authorized_keys_path(path: &str) -> bool {
    path.ends_with("/.ssh/authorized_keys")
        || path.ends_with("/.ssh/authorized_keys2")
        || path == "/etc/ssh/authorized_keys"
        || path
            .strip_prefix("/etc/ssh/authorized_keys/")
            .is_some_and(|leaf| !leaf.is_empty() && !leaf.contains('/'))
}

// ── NN-L-FIM-005 — log file truncated ──────────────────────────────

/// Modification of a `/var/log/` or `/var/audit/` file where
/// the new SHA differs AND the file SHRUNK (post-mod size <
/// baseline size). High severity; **action: log only** — many
/// legit operators truncate logs (logrotate, manual cleanup),
/// killing the modifier (often `logrotate`) is the wrong
/// response. The audit chain captures the event so an
/// investigator can see "log /var/log/auth.log shrunk from
/// 4 MB to 0 at T by uid=… pid=… comm=…".
///
/// Fires on any `Modified` op against these paths and lets the
/// operator distinguish real tampering via the drift log's
/// `baseline_sha256` + `new_sha256` fields, EXCEPT for the one
/// high-volume false positive carved out below.
///
/// ## FP-1 carve-out — rsyslogd's own log appends
///
/// `rsyslogd` appends to `/var/log/{syslog,kern,auth}.log` (and
/// friends) continuously; under the old "fire on *any* Modified"
/// rule that tripped NN-L-FIM-005 on every flush. The carve-out
/// suppresses the verdict ONLY when ALL three hold — anything else
/// still fires (action: Log):
///   (a) the writer's `/proc/<pid>/exe` is the rsyslog daemon
///       ([`RSYSLOGD_EXES`]) — kernel-resolved, not `comm`;
///   (b) the writer's uid is the `syslog` system user
///       ([`Self::syslog_uid`], resolved once at construction);
///   (c) the file GREW (`new_size > baseline_size`) — an append.
///       A shrink/truncation, or unknown sizes, is NOT exempted.
///
/// So a non-rsyslogd writer, a uid mismatch, OR a truncation on a
/// log path all still raise the verdict. Sizes ride on the
/// `FimEvent` from the drain's re-hash (`new_size`) and the
/// diverged baseline (`baseline_size`); the rule stays a pure
/// function of the event (no `/proc` reads here — that resolution
/// happens upstream in the drain).
///
/// ## FP-6 carve-out — binary login-record logs
///
/// `/var/log/{wtmp,lastlog,btmp}` fall in this rule's `/var/log`
/// scope but are owned by the login-aware rules NN-L-FIM-018/019,
/// which fire ONLY when a NON-login process rewrites them. A normal
/// login writes these via PAM / `login` every session — not a
/// truncation, yet a `Modified` op on a `/var/log` path, so under the
/// bare scope match this rule tripped its High verdict on every admin
/// login. Those three exact paths ([`LASTLOG_PATHS`] ∪
/// [`WTMP_BTMP_PATHS`]) are therefore deferred entirely to -018/-019;
/// a real wipe is a non-login writer on them and is still caught
/// there. Coverage of the rest of `/var/log` is unchanged.
pub struct NnLFim005LogTruncated {
    /// uid of the `syslog` system user, resolved once when the
    /// engine is built (a `/etc/passwd` parse — see
    /// [`resolve_uid_by_name`]). `None` on a host with no `syslog`
    /// user: the rsyslogd-append carve-out then never applies and
    /// the rule fires as before (fail toward alerting).
    syslog_uid: Option<u32>,
}

impl NnLFim005LogTruncated {
    /// Build the rule with the host's resolved `syslog` uid (or
    /// `None` if absent / unresolved). [`fim_rules`] passes the
    /// live value; tests pass a fixture uid.
    pub fn new(syslog_uid: Option<u32>) -> Self {
        Self { syslog_uid }
    }

    /// True iff this Modified-on-log-path event is rsyslogd's own
    /// routine append — the FP-1 carve-out (a) ∧ (b) ∧ (c). Pure;
    /// reads only `FimEvent` fields populated upstream by the drain.
    fn is_rsyslogd_append(&self, fe: &FimEvent) -> bool {
        // (a) writer exe is the rsyslog daemon (exact, kernel-resolved).
        let exe_match = fe
            .modifier_exe
            .as_deref()
            .is_some_and(|exe| RSYSLOGD_EXES.contains(&exe));
        // (b) writer uid is the syslog system user.
        let uid_match = self
            .syslog_uid
            .is_some_and(|syslog| fe.modifier_uid == syslog);
        // (c) the file grew — an append, not a truncation. Unknown
        // sizes on either side fail this check (→ rule still fires).
        let grew = matches!(
            (fe.new_size, fe.baseline_size),
            (Some(new), Some(base)) if new > base
        );
        exe_match && uid_match && grew
    }
}

impl Rule for NnLFim005LogTruncated {
    fn id(&self) -> &'static str {
        "NN-L-FIM-005_LogTruncated"
    }
    fn name(&self) -> &'static str {
        "Log file modified (truncation suspect)"
    }
    fn category(&self) -> &'static str {
        "fim_defense_evasion"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if fe.op != FimOp::Modified {
            return None;
        }
        if !starts_with_any(&fe.path, LOG_ROOT_PREFIXES) {
            return None;
        }
        // FP-6: the binary login-record logs (wtmp/lastlog/btmp) sit in
        // the /var/log scope but are owned by the login-aware rules
        // NN-L-FIM-018/019 (they fire only on a non-login writer). A
        // normal login rewrites these every session — not a truncation —
        // so defer those three exact paths entirely; a real wipe is a
        // non-login writer there and is still caught by -018/-019.
        if LASTLOG_PATHS
            .iter()
            .chain(WTMP_BTMP_PATHS.iter())
            .any(|p| fe.path == *p)
        {
            return None;
        }
        // FP-1: rsyslogd's own appends are not tampering — suppress.
        if self.is_rsyslogd_append(fe) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::Log,
            Severity::High,
            "Log file modified — possible truncation / log-tampering",
        ))
    }
}

// ── NN-L-FIM-006 — operator-installed binary modified ──────────────

/// Modification of files under `/usr/local/bin/`,
/// `/usr/local/sbin/`, or `/opt/`. Medium severity — most
/// modifications here are legitimate operator-installed
/// software upgrades, but unexpected changes are worth
/// surfacing for review.
pub struct NnLFim006OperatorBinaryModified;

impl Rule for NnLFim006OperatorBinaryModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-006_OperatorBinaryModified"
    }
    fn name(&self) -> &'static str {
        "Operator-installed binary modified"
    }
    fn category(&self) -> &'static str {
        "fim_supply_chain"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if fe.op != FimOp::Modified {
            return None;
        }
        if !starts_with_any(&fe.path, OPERATOR_BIN_PREFIXES) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::Log,
            Severity::Medium,
            "Operator-installed binary modified",
        ))
    }
}

// ── NN-L-FIM-007 — cron drop-in created ────────────────────────────

/// FP-3 coalescing window for ONE logical cron edit. 2 s comfortably
/// spans the multi-syscall op-sequence of a single `crontab` install /
/// atomic editor save (create + content writes + setattr, all µs
/// apart) while staying far below the cadence of any plausible distinct
/// operator edit of the same file.
const CRON_DEDUP_WINDOW_NS: u64 = 2_000_000_000;

/// Normalize a cron path to its dedup *bucket* — the [`CRON_DROPIN_PATHS`]
/// root it falls under, trailing slash trimmed (`/var/spool/cron`,
/// `/etc/cron.d`, `/etc/crontab`, …). Returns `None` for a non-cron path,
/// so this doubles as the rule's path-match check. The bucket is
/// `&'static str` (it IS the matched root), so the key never allocates.
///
/// External audit NN-AUD-288 (FIMR-014): a directory entry (it ends in
/// `/`) covers what lies below it; a file entry (`/etc/crontab`) only
/// itself. `/etc/crontab.bak` matched the file's prefix, fired the rule
/// and shared the real crontab's bucket.
fn cron_dedup_bucket(path: &str) -> Option<&'static str> {
    CRON_DROPIN_PATHS
        .iter()
        .copied()
        .find(|root| {
            if root.ends_with('/') {
                path.starts_with(root)
            } else {
                path == *root
            }
        })
        .map(|root| root.strip_suffix('/').unwrap_or(root))
}

/// External audit NN-AUD-285: the most fires [`CronEditWindow`] remembers
/// at once. Beyond, the oldest is forgotten: a later event of its edit
/// fires again (toward detection).
const CRON_FIRES_MAX: usize = 1024;

/// One NN-L-FIM-007 verdict fired, as [`CronEditWindow`] remembers it.
#[derive(Debug)]
struct CronFire {
    pid: u32,
    bucket: &'static str,
    fired_ns: u64,
    path: String,
    /// The file it is about: the event's own, or — fired without one —
    /// the first one a later event names for it.
    file: Option<InodeKey>,
    /// A watched directory's own event.
    dir: bool,
}

/// FP-4 dedup state for NN-L-FIM-007, keyed on the file (external audit
/// NN-AUD-285, FIMR-011). A single `crontab -e` (or an editor's atomic save
/// of `/etc/crontab`) is atomic yet drives the kernel FIM hooks several
/// times across the THREE distinct paths of one logical edit — the temp
/// file, the renamed-into-place crontab, and the spool directory itself —
/// so the drain emits ~6 `Event::Fim`s for one persistence event. Keying
/// on `(pid, directory bucket)` collapsed them, and with them every other
/// drop-in the same process wrote within the window: a second
/// `/etc/cron.d/job-b` drew no verdict. The edit is now told by the file
/// ([`FimEvent::file_key`]): the temporary file renamed into place keeps
/// its inode, two drop-ins are two inodes, whatever their names.
///
/// Within [`CRON_DEDUP_WINDOW_NS`] of a fire for the same `(pid, bucket)`:
/// - an event naming a file already fired for is part of that edit;
/// - a watched directory's own event ([`FimEvent::is_dir`]) is part of the
///   edit that changed it;
/// - an event naming a new file is part of an edit fired without one when
///   it is on that fire's path, or when the file was moved in
///   ([`FimEvent::moved_in`]: the drain could not read the temporary file
///   before it was renamed on);
/// - an event whose file the drain could not tell is part of an edit on
///   the same path, or, moved in, of any edit (the rename had not landed
///   when the drain looked);
/// - anything else fires: a new file created under a new name, by the same
///   process, is a new drop-in.
///
/// The window is anchored on the FIRE (a suppressed repeat does NOT extend
/// it), so a sustained drip still surfaces roughly every window.
///
/// Stateful-rule precedent: mirrors NN-L-NET-005's
/// [`DnsBurstWindow`](crate::decision::rules::net::DnsBurstWindow) —
/// `&mut self` behind an `Arc<Mutex<_>>`, clocked by the event-carried
/// `timestamp_ns` (no syscall clock, so the rule stays a pure function
/// of the event + its own state).
#[derive(Debug, Default)]
pub struct CronEditWindow {
    fires: VecDeque<CronFire>,
}

impl CronEditWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the cron event `fe`, in `bucket`, and report whether
    /// NN-L-FIM-007 should FIRE for it (see [`CronEditWindow`]). Fires
    /// older than the window are dropped on every call, so in steady state
    /// (cron writes are rare) the window is empty.
    pub fn observe(&mut self, fe: &FimEvent, bucket: &'static str) -> bool {
        let ts_ns = fe.timestamp_ns;
        self.fires
            .retain(|f| ts_ns.saturating_sub(f.fired_ns) < CRON_DEDUP_WINDOW_NS);
        let pid = fe.modifier_pid;
        let mut same = self
            .fires
            .iter_mut()
            .filter(|f| f.pid == pid && f.bucket == bucket)
            .peekable();
        let part_of_an_edit = if same.peek().is_none() {
            false
        } else if fe.is_dir {
            true
        } else if let Some(file) = fe.file_key {
            let mut fires: Vec<&mut CronFire> = same.collect();
            if fires.iter().any(|f| f.file == Some(file)) {
                true
            } else if let Some(open) = fires
                .iter_mut()
                .find(|f| !f.dir && f.file.is_none() && (f.path == fe.path || fe.moved_in))
            {
                open.file = Some(file);
                true
            } else {
                false
            }
        } else {
            let moved_in = fe.moved_in;
            same.any(|f| moved_in || f.path == fe.path)
        };
        if part_of_an_edit {
            return false;
        }
        if self.fires.len() >= CRON_FIRES_MAX {
            self.fires.pop_front();
        }
        self.fires.push_back(CronFire {
            pid,
            bucket,
            fired_ns: ts_ns,
            path: fe.path.clone(),
            file: fe.file_key,
            dir: fe.is_dir,
        });
        true
    }
}

/// `Created` op against any of the cron drop-in roots. High
/// severity — MITRE T1053.003 (Cron) is the canonical
/// scheduled-task persistence vector. Includes
/// `/etc/crontab` as an exact-match path (NN-AUD-288: equality, not a
/// prefix).
///
/// FP-3 dedup: a single logical crontab edit drives the FIM hooks
/// several times (create + writes + setattr), which previously raised ~6
/// identical KillProcess verdicts. The rule holds a [`CronEditWindow`] and
/// fires ONCE per edit — per file, NN-AUD-285 — within
/// [`CRON_DEDUP_WINDOW_NS`]; distinct files, pids and cron directories,
/// and the same file after the window, still fire.
pub struct NnLFim007CronDropInCreated {
    dedup: Arc<Mutex<CronEditWindow>>,
}

impl NnLFim007CronDropInCreated {
    /// Build with a caller-supplied dedup window (symmetry with the
    /// NN-L-NET stateful-rule factories; lets a test share / inspect it).
    pub fn new(dedup: Arc<Mutex<CronEditWindow>>) -> Self {
        Self { dedup }
    }

    /// Convenience: allocate a fresh, rule-private dedup window. Used by
    /// [`fim_rules`] (one window per engine) and the unit tests.
    pub fn with_fresh_window() -> Self {
        Self::new(Arc::new(Mutex::new(CronEditWindow::new())))
    }
}

impl Rule for NnLFim007CronDropInCreated {
    fn id(&self) -> &'static str {
        "NN-L-FIM-007_CronDropInCreated"
    }
    fn name(&self) -> &'static str {
        "Cron drop-in created"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        // Either Created (new drop-in file) OR Modified
        // (crontab edited in-place). Both signal a persistence
        // event.
        if !matches!(fe.op, FimOp::Created | FimOp::Modified) {
            return None;
        }
        let bucket = cron_dedup_bucket(&fe.path)?;
        // FP-4: collapse the multi-FIM-op burst of ONE logical edit into a
        // single verdict. A crontab install is atomic but touches three
        // distinct paths — temp file, renamed-into-place crontab, and the
        // spool directory. NN-AUD-285: one edit is one file (the temporary
        // file renamed into place keeps its inode); a second drop-in by the
        // same process is a second file and fires.
        if !self.dedup.lock().observe(fe, bucket) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcess,
            Severity::High,
            "Cron drop-in created or modified — persistence indicator",
        ))
    }
}

// ── NN-L-FIM-008 — kernel module file modified ─────────────────────

/// Creation or modification of any file under `/lib/modules/`.
/// Critical — a dropped or modified kernel module is a rootkit-class
/// compromise (MITRE T1014 Rootkit + T1547.006 Boot/Logon Autostart
/// Execution: Kernel Modules). BUG-022: the `Created` arm is what
/// catches a NEW `.ko` dropped into a watched modules dir — the child
/// leaf is now reconstructed so the `/lib/modules/` prefix matches.
pub struct NnLFim008KernelModuleModified;

impl Rule for NnLFim008KernelModuleModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-008_KernelModuleModified"
    }
    fn name(&self) -> &'static str {
        "Kernel module file modified"
    }
    fn category(&self) -> &'static str {
        "fim_rootkit"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Created | FimOp::Modified) {
            return None;
        }
        if !fe.path.starts_with(KMOD_PREFIX) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "Kernel module file created or modified — rootkit indicator",
        ))
    }
}

// ── NN-L-FIM-009 — systemd unit file dropped/modified ──────────────

/// `Created` or `Modified` op against any systemd unit
/// directory. High severity — MITRE T1543.002 (Systemd
/// Service) is a persistence vector second only to cron in
/// prevalence.
///
/// ## FIM-009 self-upgrade downgrade (§15.1)
///
/// When a trusted-installer window is OPEN
/// ([`TrustedInstallerOverride::is_window_open`]), a write to the
/// agent's OWN units ([`OWN_SYSTEMD_UNITS`]) is an authorised in-place
/// upgrade: the verdict is DOWNGRADED from `KillProcess`/High to an
/// audit-level `Log`/Low — recorded, never silenced. The scope is
/// tight: a write to ANY OTHER unit path still trips the kill even
/// inside a window, and once the window closes (TTL / boot) our own
/// units trip the kill again. The override read is pure (an atomic load
/// and a deadline compare, no I/O), so the rule stays a pure function of
/// the event plus the shared state — the same discipline as the FP carve-outs.
pub struct NnLFim009SystemdUnitDropped {
    installer_override: Arc<TrustedInstallerOverride>,
}

impl NnLFim009SystemdUnitDropped {
    /// Build with the shared trusted-installer override. [`fim_rules`]
    /// passes the live handle; the default/test rule sets pass
    /// [`TrustedInstallerOverride::inert_arc`] (never armed → the rule
    /// behaves exactly as it did before §15.1).
    pub fn new(installer_override: Arc<TrustedInstallerOverride>) -> Self {
        Self { installer_override }
    }
}

impl Rule for NnLFim009SystemdUnitDropped {
    fn id(&self) -> &'static str {
        "NN-L-FIM-009_SystemdUnitDropped"
    }
    fn name(&self) -> &'static str {
        "Systemd unit file dropped or modified"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Created | FimOp::Modified) {
            return None;
        }
        if !starts_with_any(&fe.path, SYSTEMD_UNIT_PREFIXES) {
            return None;
        }
        // §15.1: inside an OPEN trusted-installer window, a write to the
        // agent's OWN unit files is an authorised upgrade — downgrade to
        // an audit Log (recorded, not silenced). Tight scope: any other
        // unit, or our units with no open window, still trip the kill.
        if OWN_SYSTEMD_UNITS.contains(&fe.path.as_str()) && self.installer_override.is_window_open()
        {
            return Some(fim_verdict(
                self,
                fe,
                ResponseAction::Log,
                Severity::Low,
                "Systemd unit file written under an OPEN trusted-installer window \
                 (agent's own unit) — authorised in-place upgrade, audit-only",
            ));
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcess,
            Severity::High,
            "Systemd unit file dropped or modified — persistence indicator",
        ))
    }
}

// ── NN-L-FIM-010 — ransomware extension rename (C5.1) ──────────────

/// Curated list of file extensions strongly indicative of
/// ransomware-driven file rename (the classic "encrypt + rename
/// to a marker extension" loop). Port of the legacy M14.4
/// NN-L-FIM-001 rule into the new C5 architecture.
///
/// MUST stay extension-only (e.g. `.locked`, never `.lock`) so
/// legitimate `.lock` PID files in `/var/run/`, `/run/`, `/tmp/`
/// don't match. Match policy is `ends_with(".<ext>")` (the leading
/// dot is part of the check) so a file literally named "locked"
/// or "encrypted" doesn't false-positive either.
///
/// Curated, not exhaustive — operators with a known ransomware
/// strain in their threat model add to this list via a future
/// `fim-ransomware-extensions.local` override (V1.1). The V1.0
/// list covers the most-prevalent strains seen in EDR
/// telemetry per the legacy M14.4 commit + recent IR reports.
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    // Generic ransomware markers (most-common file extensions
    // after the encrypt loop).
    ".crypted",
    ".locked",
    ".encrypted",
    ".crypto",
    ".crypt",
    ".vault",
    ".crinf",
    ".ezz",
    ".exx",
    ".xyz",
    ".ttt",
    ".micro",
    ".xxx",
    // Strain-specific markers (named-attribution).
    ".ryk",      // Ryuk
    ".wannacry", // WannaCry
    ".wcry",     // WannaCry (alt)
    ".conti",    // Conti
    ".lockbit",  // LockBit
    ".blackcat", // ALPHV/BlackCat
];

/// One of the [`RANSOMWARE_EXTENSIONS`] ends `path`, in any case. External
/// audit NN-AUD-287 (FIMR-013): the list is lowercase, and `.LOCKED` or
/// `.Crypted` went unmatched. Compared on bytes: the extensions are ASCII.
fn has_ransomware_extension(path: &str) -> bool {
    let path = path.as_bytes();
    RANSOMWARE_EXTENSIONS.iter().any(|ext| {
        path.len() >= ext.len()
            && path[path.len() - ext.len()..].eq_ignore_ascii_case(ext.as_bytes())
    })
}

/// Ransomware extension rename per legacy M14.4 NN-L-FIM-001,
/// restored into the C5 architecture as NN-L-FIM-010.
///
/// Detection: `FimOp::Renamed` event whose path ends with one
/// of the [`RANSOMWARE_EXTENSIONS`]. Critical severity (MITRE
/// T1486 Data Encrypted for Impact); response is
/// `KillProcessTree` of the modifier — the ransomware loop is
/// running and we want to stop it before it traverses more of
/// the filesystem. Never throttled by §6.5 rate limiter per
/// Q4 lock-in (Critical tier).
///
/// **False-positive guards (asserted in tests):**
/// - `.lock` PID files in `/var/run/`, `/run/`, `/tmp/` — NOT
///   in the extension list (we match `.locked` not `.lock`).
/// - `.tmp`, `.bak`, `.swp`, `.swo`, `.bup` — editor + admin
///   convention; never in the list.
/// - Caller in `PROTECTED_PIDS` — already filtered by the C2
///   BPF program's `should_emit` (PHASE_D_002-symmetric
///   `caller_is_in_family` check); FIM events that reach the
///   rule layer have already been screened.
pub struct NnLFim010RansomwareExtensionRename;

impl Rule for NnLFim010RansomwareExtensionRename {
    fn id(&self) -> &'static str {
        "NN-L-FIM-010_RansomwareExtensionRename"
    }
    fn name(&self) -> &'static str {
        "Ransomware extension rename"
    }
    fn category(&self) -> &'static str {
        "fim_impact_ransomware"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if fe.op != FimOp::Renamed {
            return None;
        }
        // Polish #3: check the DEST path (canonical ransomware
        // case: watched `<doc>.docx` renamed to `<doc>.docx.crypted`
        // — `fe.path` is still the source watched path, `fe.dest_path`
        // carries the new name once C8's drain resolved it). The
        // src-side check stays as the fallback (symmetric edge:
        // a watched `<doc>.crypted` being renamed away by the
        // operator — rare but consistent).
        let dest_match = fe
            .dest_path
            .as_deref()
            .is_some_and(has_ransomware_extension);
        let src_match = has_ransomware_extension(&fe.path);
        if !dest_match && !src_match {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "Ransomware extension rename — MITRE T1486 (Data Encrypted for Impact); \
             kill the modifier tree to halt the encrypt loop",
        ))
    }
}

// ── NN-L-FIM-011..014 — cloud credentials read (C5.3) ─────────────

/// Substring fragments that identify cloud-credential file
/// paths for the four NN-L-FIM-011..014 rules. Match policy is
/// `path.contains(<fragment>)` — substring rather than prefix
/// so both `/home/<user>/.aws/credentials` AND
/// `/root/.aws/credentials` match the same `/.aws/` fragment.
/// Curated, not exhaustive; operators extend via future
/// `fim-cred-paths.local` (V1.1).
const AWS_CRED_FRAGMENTS: &[&str] = &["/.aws/credentials", "/.aws/config"];
const AZURE_CRED_FRAGMENTS: &[&str] = &["/.azure/"];
const GCP_CRED_FRAGMENTS: &[&str] = &[
    "/.config/gcloud/credentials.db",
    "/.config/gcloud/legacy_credentials/",
    "/.config/gcloud/access_tokens.db",
    "/.config/gcloud/application_default_credentials.json",
];
const DOCKER_CRED_FRAGMENTS: &[&str] =
    &["/.docker/config.json", "/var/lib/docker/credentials.json"];

/// Review 85: each cloud's own client, as [`OwnClient`] names it: an exe
/// or script basename (`.py` dropped), or a runtime tree that only the
/// client installs (`/opt/az/`, the Azure CLI's bundled Python). Matched
/// on what the kernel executed, inside a root-owned system tree, never
/// on `comm`.
const AWS_CLIENTS: &[&str] = &["aws", "aws-cli"];
const AZURE_CLIENTS: &[&str] = &["az", "/opt/az/"];
const GCP_CLIENTS: &[&str] = &["gcloud", "gsutil", "bq"];
const DOCKER_CLIENTS: &[&str] = &["docker", "dockerd", "containerd"];

/// Common shape for the 4 cred-read rules — every rule
/// follows the same op + path-fragment pattern, the cloud's own CLI
/// exempted by [`OwnClient`]. Extracted into a single helper so
/// each rule body stays a 1-line config block.
///
/// External audit NN-AUD-286 (FIMR-012): an open of the file (a read, or
/// a write in place: a write-open always reports `Opened`), and also a
/// change that never opens it — the file replaced by a rename over it
/// (`mv new ~/.aws/credentials`, reported as `Modified`), a truncate by
/// path (`Modified`), a chmod or chown (`AttrChanged`). Those drew no
/// verdict: swapping in an attacker's credentials, or opening the file to
/// every user, went unremarked.
fn evaluate_cred_read(
    rule: &dyn Rule,
    event: &Event,
    path_fragments: &[&str],
    reasoning: &str,
) -> Option<Verdict> {
    let fe = as_fim(event)?;
    if !matches!(fe.op, FimOp::Opened | FimOp::Modified | FimOp::AttrChanged) {
        return None;
    }
    if !path_fragments.iter().any(|f| fe.path.contains(f)) {
        return None;
    }
    // Review 85: the cloud's own CLI is exempted by [`OwnClient`], which
    // reads what the kernel executed; this rule fires for every reader.
    let changed;
    let reasoning = if fe.op == FimOp::Opened {
        reasoning
    } else {
        changed = format!(
            "{reasoning} [the file was changed without being opened ({:?}): replaced by a \
             rename over it, truncated, or its mode or owner changed]",
            fe.op
        );
        changed.as_str()
    };
    Some(fim_verdict(
        rule,
        fe,
        ResponseAction::KillProcess,
        Severity::High,
        reasoning,
    ))
}

/// NN-L-FIM-011 — AWS credentials read by a non-CLI process.
/// MITRE T1552.001 (Unsecured Credentials: Credentials In Files).
pub struct NnLFim011AwsCredsRead;

impl Rule for NnLFim011AwsCredsRead {
    fn id(&self) -> &'static str {
        "NN-L-FIM-011_AwsCredsRead"
    }
    fn name(&self) -> &'static str {
        "AWS credentials read by non-CLI process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_read(
            self,
            event,
            AWS_CRED_FRAGMENTS,
            "AWS credentials read by a process other than aws-cli — \
             MITRE T1552.001 indicator",
        )
    }
}

/// NN-L-FIM-012 — Azure credentials read by a non-CLI process.
/// MITRE T1552.001.
pub struct NnLFim012AzureCredsRead;

impl Rule for NnLFim012AzureCredsRead {
    fn id(&self) -> &'static str {
        "NN-L-FIM-012_AzureCredsRead"
    }
    fn name(&self) -> &'static str {
        "Azure credentials read by non-CLI process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_read(
            self,
            event,
            AZURE_CRED_FRAGMENTS,
            "Azure credentials read by a process other than az — \
             MITRE T1552.001 indicator",
        )
    }
}

/// NN-L-FIM-013 — GCP credentials read by a non-CLI process.
/// MITRE T1552.001. Covers both the modern credentials.db and
/// the legacy `legacy_credentials/` directory layout.
pub struct NnLFim013GcpCredsRead;

impl Rule for NnLFim013GcpCredsRead {
    fn id(&self) -> &'static str {
        "NN-L-FIM-013_GcpCredsRead"
    }
    fn name(&self) -> &'static str {
        "GCP credentials read by non-CLI process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_read(
            self,
            event,
            GCP_CRED_FRAGMENTS,
            "GCP credentials read by a process other than gcloud/gsutil/bq — \
             MITRE T1552.001 indicator",
        )
    }
}

/// NN-L-FIM-014 — Docker registry credentials read by a
/// non-CLI process. MITRE T1552.001. Reads of the config.json
/// (operator-side) or /var/lib/docker/credentials.json (daemon-
/// side) by anything other than `docker`/`dockerd`/`containerd`
/// is a strong credential-theft indicator.
pub struct NnLFim014DockerCredsRead;

impl Rule for NnLFim014DockerCredsRead {
    fn id(&self) -> &'static str {
        "NN-L-FIM-014_DockerCredsRead"
    }
    fn name(&self) -> &'static str {
        "Docker registry credentials read by non-CLI process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_read(
            self,
            event,
            DOCKER_CRED_FRAGMENTS,
            "Docker registry creds read by a process other than docker/dockerd/containerd — \
             MITRE T1552.001 indicator",
        )
    }
}

// ════════════════════════════════════════════════════════════════════
// Tappa 10.5 D3 — NN-L-FIM-015..023 (credential stores +
// persistence / defense-evasion surface). Pure path-pattern
// additions over the shipped FIM machinery; each mirrors the
// FIM-001..014 shape (stateless struct + `as_fim` + `fim_verdict`).
// The family allowlist is the `fim-paths.{v1,local}` watched set
// (§13 Q3); per-rule const comm whitelists exempt the legitimate
// application that owns each credential store.
// ════════════════════════════════════════════════════════════════════

// ── D3 path-fragment + comm-whitelist sets ──────────────────────────

/// NN-L-FIM-015: browser stored-credential file fragments. Chrome/
/// Chromium/Edge/Brave keep logins in an SQLite `Login Data`;
/// Firefox in `logins.json` + the NSS key DB `key4.db` (legacy
/// `key3.db` / `signons.sqlite`). Matched with `contains` so the
/// per-user/per-profile prefix is irrelevant.
const BROWSER_CRED_FRAGMENTS: &[&str] = &[
    "/Login Data",
    "logins.json",
    "key4.db",
    "key3.db",
    "signons.sqlite",
];

/// The browsers that legitimately read their own credential store —
/// exempted by [`OwnClient`] so the rule fires on any other process
/// touching the file (the exfil shape).
const BROWSER_CLIENTS: &[&str] = &[
    "chrome",
    "chromium",
    "firefox",
    "firefox-bin",
    "firefox-esr",
    "brave",
    "msedge",
    "opera",
    "vivaldi",
    "vivaldi-bin",
];

/// NN-L-FIM-016: password-manager database fragments — KeePass
/// `*.kdbx` + the `pass` store directory.
const PASSWORD_MANAGER_FRAGMENTS: &[&str] = &[".kdbx", "/.password-store/"];

/// Password managers that legitimately read their own store (KeePass 2
/// runs as `KeePass.exe` under mono; `pass` is a shell script).
const PASSWORD_MANAGER_CLIENTS: &[&str] = &[
    "keepassxc",
    "keepassxc-cli",
    "keepass",
    "keepass2",
    "KeePass.exe",
    "pass",
    "gopass",
];

/// NN-L-FIM-017: GPG keyring directory fragment.
const GPG_KEYRING_FRAGMENTS: &[&str] = &["/.gnupg/"];

/// The GnuPG toolchain that legitimately reads the keyring.
const GPG_CLIENTS: &[&str] = &[
    "gpg",
    "gpg2",
    "gpg-agent",
    "gpgconf",
    "gpgsm",
    "dirmngr",
    "keyboxd",
    "scdaemon",
    "gpg-connect-agent",
];

/// `true` if this FIM event is an access (read or write) of any
/// credential-store path that NN-L-FIM-015/016/017 watch (browser
/// login stores, password-manager DBs, GPG keyrings). Single source
/// of truth for the "credential-store FIM hit" signal — Tappa 10.5
/// D5's NN-L-CHAIN-001 reuses it as the chain precursor so the
/// fragment lists never drift between the FIM rules and the chain.
/// Note: this does NOT apply the per-app comm exemption the FIM
/// rules use — the chain rule wants the precursor recorded for ANY
/// accessor (the correlation with egress is what makes it Critical).
pub fn is_credential_store_access(fe: &FimEvent) -> bool {
    if !matches!(fe.op, FimOp::Opened | FimOp::Modified) {
        return false;
    }
    BROWSER_CRED_FRAGMENTS
        .iter()
        .chain(PASSWORD_MANAGER_FRAGMENTS.iter())
        .chain(GPG_KEYRING_FRAGMENTS.iter())
        .any(|f| fe.path.contains(f))
}

/// External audit FIMR-005: a path one of the Critical rules guards —
/// system binaries (NN-L-FIM-001), kernel modules (008), PAM modules
/// (021), `/etc/ld.so.preload` (022), the anti-tamper baits (024). The
/// drain never throttles a drift on one of them (§6.5, Q4). Built from the
/// rules' own constants, like [`is_credential_path`].
pub fn is_critical_rule_path(path: &str) -> bool {
    SYSTEM_BINARY_PREFIXES.iter().any(|p| path.starts_with(p))
        || path.starts_with(KMOD_PREFIX)
        || (path.contains(PAM_MODULE_DIR_FRAGMENT) && path.ends_with(PAM_MODULE_SUFFIX))
        || path == LD_SO_PRELOAD_PATH
        || HONEYPOT_PATHS.contains(&path)
}

/// BUG-012 (v2): `true` if `path` is a credential file that one of
/// the NN-L-FIM-011..017 **read**-detection rules matches on. This is
/// the SINGLE SOURCE OF TRUTH the FIM drain
/// (`fim::drain::process_drift`) consults to decide whether an
/// `Opened` (read) event must still flow to the rule engine.
///
/// A read is not an integrity change, so `Opened` never produces a
/// FIM-DRIFT row. But for these credential paths the `Opened` event is
/// the ONLY source feeding the cloud-cred (011..014,
/// [`evaluate_cred_read`]) and browser / password-manager / GPG
/// keyring (015..017, [`evaluate_cred_store_access`]) read rules —
/// dropping it at the drain would silently kill credential-theft-read
/// detection. By deriving this predicate from the very fragment lists
/// those rules match, the drain forwards exactly — and only — the
/// `Opened` events some rule can consume; a read of any OTHER watched
/// path carries no rule and is dropped as noise. The
/// `bug012_v2_is_credential_path_matches_every_rule_family` test pins
/// that this stays in lockstep with the rule fragment lists.
pub fn is_credential_path(path: &str) -> bool {
    AWS_CRED_FRAGMENTS
        .iter()
        .chain(AZURE_CRED_FRAGMENTS.iter())
        .chain(GCP_CRED_FRAGMENTS.iter())
        .chain(DOCKER_CRED_FRAGMENTS.iter())
        .chain(BROWSER_CRED_FRAGMENTS.iter())
        .chain(PASSWORD_MANAGER_FRAGMENTS.iter())
        .chain(GPG_KEYRING_FRAGMENTS.iter())
        .any(|f| path.contains(f))
}

/// NN-L-FIM-018: the login-record file `utmp`-family writers
/// legitimately rewrite. A Modified op by anything else is the
/// log-tamper shape.
const LASTLOG_PATHS: &[&str] = &["/var/log/lastlog"];

/// NN-L-FIM-019: the binary login-record logs (`wtmp` = successful
/// logins, `btmp` = failed). Same legitimate-writer set as -018.
const WTMP_BTMP_PATHS: &[&str] = &["/var/log/wtmp", "/var/log/btmp"];

/// The login-session machinery that legitimately appends to the
/// `utmp`-family records (via the libc utmp API), by the exe basename
/// [`OwnClient`] reads. A write by any other program is the tamper shape
/// NN-L-FIM-018/019 catch.
///
/// - `sshd-session`: OpenSSH >= 9.8 moved the per-session monitor (which
///   records the wtmp login and the btmp failed login) into it (Debian
///   13, Ubuntu 24.10+, RHEL 10).
/// - `systemd-update-utmp`: boot, shutdown and runlevel records (review
///   item 38).
/// - `systemd-executor`, `systemd`: a unit's `UtmpIdentifier=` record is
///   written by the forked child before it execs the unit's program (as
///   `systemd-executor` on systemd >= 255, else still as PID 1's exe);
///   its `comm` then reads `(agetty)` (review item 38).
const LOGIN_RECORD_WRITERS: &[&str] = &[
    "login",
    "sshd",
    "sshd-session",
    "systemd-logind",
    "systemd-update-utmp",
    "systemd-executor",
    "init",
    "systemd",
    "getty",
    "agetty",
    "mingetty",
    "lightdm",
    "gdm",
    "gdm3",
    "gdm-session-worker",
    "su",
    "sudo",
    "lastlog",
    "lastlog2",
];

/// Review 83: the account tools that write `/etc/passwd`, `/etc/shadow`
/// and `/var/log/lastlog` by design (shadow-utils, libuser, systemd), by
/// exe basename.
const ACCOUNT_TOOLS: &[&str] = &[
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "expiry",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "chpasswd",
    "chgpasswd",
    "newusers",
    "pwconv",
    "pwunconv",
    "grpconv",
    "grpunconv",
    "vipw",
    "vigr",
    "pwck",
    "grpck",
    "systemd-sysusers",
    "luseradd",
    "lusermod",
    "luserdel",
    "lgroupadd",
    "lgroupmod",
    "lgroupdel",
    "lpasswd",
    "lchage",
    "lchfn",
    "lchsh",
    "lnewusers",
];

/// NN-L-FIM-020: shell-history file fragments. The clear-history
/// attack deletes or renames these (truncate-in-place is
/// indistinguishable from a normal append at the rule layer without
/// file size — deferred; the Deleted/Renamed signal is unambiguous).
const SHELL_HISTORY_FRAGMENTS: &[&str] = &[".bash_history", ".zsh_history"];

/// NN-L-FIM-021: PAM modules live under a `security/` directory and
/// end in `.so`. The arch-specific lib dir varies
/// (`/lib/security/`, `/usr/lib/x86_64-linux-gnu/security/`, …), so
/// the `/security/` fragment + `.so` suffix is the portable match.
const PAM_MODULE_DIR_FRAGMENT: &str = "/security/";
const PAM_MODULE_SUFFIX: &str = ".so";

/// NN-L-FIM-022: the dynamic-linker preload file. Its mere presence
/// is a near-certain LD_PRELOAD-rootkit indicator (it legitimately
/// does not exist on a stock host).
const LD_SO_PRELOAD_PATH: &str = "/etc/ld.so.preload";

/// NN-L-FIM-023: systemd timer units end in `.timer` and live under
/// the same unit dirs as NN-L-FIM-009 ([`SYSTEMD_UNIT_PREFIXES`]).
const SYSTEMD_TIMER_SUFFIX: &str = ".timer";

// ── D3 shared helpers ───────────────────────────────────────────────

/// Shared shape for the credential-store access rules
/// (NN-L-FIM-015/016/017): a read (`Opened`) OR write (`Modified`)
/// of a credential file by a process OTHER than the store's own
/// application. Mirrors [`evaluate_cred_read`] but widens the op set
/// to include writes (a write to a browser/PM/GPG store by a foreign
/// process is also an indicator). High + KillProcess.
fn evaluate_cred_store_access(
    rule: &dyn Rule,
    event: &Event,
    path_fragments: &[&str],
    reasoning: &str,
) -> Option<Verdict> {
    let fe = as_fim(event)?;
    if !matches!(fe.op, FimOp::Opened | FimOp::Modified) {
        return None;
    }
    if !path_fragments.iter().any(|f| fe.path.contains(f)) {
        return None;
    }
    // Review 85: the application that owns the store is exempted by
    // [`OwnClient`], which reads what the kernel executed.
    Some(fim_verdict(
        rule,
        fe,
        ResponseAction::KillProcess,
        Severity::High,
        reasoning,
    ))
}

/// Shared shape for the login-record tamper rules
/// (NN-L-FIM-018/019): a `Modified` op on an exact `utmp`-family
/// path. High + KillProcess, unless [`OwnClient`] finds the writer is
/// one of [`LOGIN_RECORD_WRITERS`].
fn evaluate_login_record_tamper(
    rule: &dyn Rule,
    event: &Event,
    exact_paths: &[&str],
    reasoning: &str,
) -> Option<Verdict> {
    let fe = as_fim(event)?;
    if fe.op != FimOp::Modified {
        return None;
    }
    if !exact_paths.iter().any(|p| fe.path == *p) {
        return None;
    }
    // Review 85: the login machinery is exempted by [`OwnClient`], which
    // reads what the kernel executed.
    Some(fim_verdict(
        rule,
        fe,
        ResponseAction::KillProcess,
        Severity::High,
        reasoning,
    ))
}

/// systemd renames a unit's forked child to `(<ExecStart basename>)`
/// (the last 8 characters when longer) between fork and exec, and that
/// pre-exec child is the one that writes the unit's `UtmpIdentifier=`
/// INIT_PROCESS record into utmp/wtmp. On systemd >= 255 it is the
/// `systemd-executor` process carrying that name. Every getty start
/// therefore writes `/var/log/wtmp` as `(agetty)` before the same PID
/// writes again as `agetty` after exec.
///
/// Strips exactly one surrounding pair of parentheses so the
/// login-record allowlist matches the real program name. Anything else
/// in parentheses (`(sed)`, `((agetty))`) still has to match the list
/// after stripping, so the exemption grants nothing beyond what the
/// bare comm already would.
fn systemd_preexec_name(comm: &str) -> &str {
    comm.strip_prefix('(')
        .and_then(|c| c.strip_suffix(')'))
        .unwrap_or(comm)
}

// ── NN-L-FIM-015 — browser stored credentials accessed ─────────────

/// Read or write of a browser credential store by a non-browser
/// process. MITRE T1555.003 (Credentials from Web Browsers).
pub struct NnLFim015BrowserCredsAccessed;

impl Rule for NnLFim015BrowserCredsAccessed {
    fn id(&self) -> &'static str {
        "NN-L-FIM-015_BrowserCredsAccessed"
    }
    fn name(&self) -> &'static str {
        "Browser stored credentials accessed by non-browser process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_store_access(
            self,
            event,
            BROWSER_CRED_FRAGMENTS,
            "Browser stored-credential file accessed by a non-browser \
             process — MITRE T1555.003; posture → ENGAGED",
        )
    }
}

// ── NN-L-FIM-016 — password-manager DB accessed ────────────────────

/// Read or write of a KeePass `*.kdbx` / `pass` store by a process
/// other than a known password manager. MITRE T1555.005 (Password
/// Managers).
pub struct NnLFim016PasswordManagerDbAccessed;

impl Rule for NnLFim016PasswordManagerDbAccessed {
    fn id(&self) -> &'static str {
        "NN-L-FIM-016_PasswordManagerDbAccessed"
    }
    fn name(&self) -> &'static str {
        "Password-manager database accessed by foreign process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_store_access(
            self,
            event,
            PASSWORD_MANAGER_FRAGMENTS,
            "Password-manager database accessed by a process other than a \
             known password manager — MITRE T1555.005; posture → ENGAGED",
        )
    }
}

// ── NN-L-FIM-017 — GPG keyring accessed ────────────────────────────

/// Read or write of `~/.gnupg/*` by a process other than the GnuPG
/// toolchain. MITRE T1552.004 (Private Keys).
pub struct NnLFim017GpgKeyringAccessed;

impl Rule for NnLFim017GpgKeyringAccessed {
    fn id(&self) -> &'static str {
        "NN-L-FIM-017_GpgKeyringAccessed"
    }
    fn name(&self) -> &'static str {
        "GPG keyring accessed by non-GnuPG process"
    }
    fn category(&self) -> &'static str {
        "fim_credential_access"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_cred_store_access(
            self,
            event,
            GPG_KEYRING_FRAGMENTS,
            "GPG keyring accessed by a process outside the GnuPG toolchain \
             — MITRE T1552.004; posture → ENGAGED",
        )
    }
}

// ── NN-L-FIM-018 — lastlog tampered ────────────────────────────────

/// Modification of `/var/log/lastlog` by a non-login-session
/// process. MITRE T1070 (Indicator Removal).
pub struct NnLFim018LastlogTampered;

impl Rule for NnLFim018LastlogTampered {
    fn id(&self) -> &'static str {
        "NN-L-FIM-018_LastlogTampered"
    }
    fn name(&self) -> &'static str {
        "lastlog tampered by non-login process"
    }
    fn category(&self) -> &'static str {
        "fim_defense_evasion"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_login_record_tamper(
            self,
            event,
            LASTLOG_PATHS,
            "/var/log/lastlog modified by a non-login process — \
             login-trace tampering (T1070); posture → ENGAGED",
        )
    }
}

// ── NN-L-FIM-019 — wtmp / btmp tampered ────────────────────────────

/// Modification of `/var/log/wtmp` or `/var/log/btmp` by a
/// non-login-session process. MITRE T1070.
pub struct NnLFim019WtmpBtmpTampered;

impl Rule for NnLFim019WtmpBtmpTampered {
    fn id(&self) -> &'static str {
        "NN-L-FIM-019_WtmpBtmpTampered"
    }
    fn name(&self) -> &'static str {
        "wtmp/btmp tampered by non-login process"
    }
    fn category(&self) -> &'static str {
        "fim_defense_evasion"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        evaluate_login_record_tamper(
            self,
            event,
            WTMP_BTMP_PATHS,
            "/var/log/wtmp or btmp modified by a non-login process — \
             login-trace tampering (T1070); posture → ENGAGED",
        )
    }
}

// ── NN-L-FIM-020 — shell history cleared ───────────────────────────

/// Deletion or rename of a shell-history file. MITRE T1070.003
/// (Clear Command History). Medium + Log — operators do clear
/// history; the audit chain records it for review.
pub struct NnLFim020ShellHistoryCleared;

impl Rule for NnLFim020ShellHistoryCleared {
    fn id(&self) -> &'static str {
        "NN-L-FIM-020_ShellHistoryCleared"
    }
    fn name(&self) -> &'static str {
        "Shell history deleted or renamed"
    }
    fn category(&self) -> &'static str {
        "fim_defense_evasion"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Deleted | FimOp::Renamed) {
            return None;
        }
        if !SHELL_HISTORY_FRAGMENTS.iter().any(|f| fe.path.contains(f)) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::Log,
            Severity::Medium,
            "Shell-history file deleted or renamed — command-history \
             clearing (T1070.003); posture → ALERTED",
        ))
    }
}

// ── NN-L-FIM-021 — PAM module modified ─────────────────────────────

/// Creation or modification of a PAM module (`*.so` under a
/// `security/` directory). MITRE T1543 / T1556 (Modify
/// Authentication Process). Critical — a malicious PAM module is a
/// credential-harvesting + auth-bypass persistence primitive.
pub struct NnLFim021PamModuleModified;

impl Rule for NnLFim021PamModuleModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-021_PamModuleModified"
    }
    fn name(&self) -> &'static str {
        "PAM module created or modified"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Created | FimOp::Modified) {
            return None;
        }
        // BUG-022: `child_truncated` means the dropped leaf overflowed
        // the inline buffer and lost its `.so` suffix — a >63-byte
        // filename in a `security/` dir is itself anomalous, so fire on
        // the dir match alone rather than let truncation be a bypass.
        if !(fe.path.contains(PAM_MODULE_DIR_FRAGMENT)
            && (fe.path.ends_with(PAM_MODULE_SUFFIX) || fe.child_truncated))
        {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "PAM module created or modified — auth-bypass / credential-harvest \
             persistence (T1543/T1556); kill tree + posture → COMBAT",
        ))
    }
}

// ── NN-L-FIM-022 — ld.so.preload modified ──────────────────────────

/// Creation or modification of `/etc/ld.so.preload`. MITRE
/// T1574.006 (Dynamic Linker Hijacking). Critical — the file is the
/// canonical LD_PRELOAD-rootkit anchor and legitimately absent on a
/// stock host, so no comm exemption is warranted.
pub struct NnLFim022LdSoPreloadModified;

impl Rule for NnLFim022LdSoPreloadModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-022_LdSoPreloadModified"
    }
    fn name(&self) -> &'static str {
        "/etc/ld.so.preload created or modified"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Created | FimOp::Modified) {
            return None;
        }
        if fe.path != LD_SO_PRELOAD_PATH {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "/etc/ld.so.preload created or modified — LD_PRELOAD rootkit \
             anchor (T1574.006); kill tree + posture → COMBAT",
        ))
    }
}

// ── NN-L-FIM-023 — systemd timer unit created ──────────────────────

/// Creation or modification of a systemd `.timer` unit under a
/// system unit directory. MITRE T1053.006 (Scheduled Task/Job:
/// Systemd Timers) — complements the NN-L-FIM-009 `.service`
/// drop-in rule.
pub struct NnLFim023SystemdTimerCreated;

impl Rule for NnLFim023SystemdTimerCreated {
    fn id(&self) -> &'static str {
        "NN-L-FIM-023_SystemdTimerCreated"
    }
    fn name(&self) -> &'static str {
        "systemd timer unit created"
    }
    fn category(&self) -> &'static str {
        "fim_persistence"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !matches!(fe.op, FimOp::Created | FimOp::Modified) {
            return None;
        }
        // BUG-022: a truncated child leaf (overflowed the inline buffer,
        // lost its `.timer` suffix) in a unit dir still fires — a
        // >63-byte unit filename is anomalous and must not be a bypass.
        if !(starts_with_any(&fe.path, SYSTEMD_UNIT_PREFIXES)
            && (fe.path.ends_with(SYSTEMD_TIMER_SUFFIX) || fe.child_truncated))
        {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcess,
            Severity::High,
            "systemd .timer unit created or modified — scheduled-task \
             persistence (T1053.006); posture → ENGAGED",
        ))
    }
}

// ── NN-L-FIM-024 — anti-tamper bait file tampered ──────────────────

/// The inert "NN control-surface" bait files (Tappa 9.5.1). Names
/// suggest a way to disable the agent (kill switches, maintenance flags,
/// override tokens); NN never reads them and no operator workflow writes
/// them, across the config (`/etc`), state (`/var/lib`) and runtime
/// (`/run`) dirs an attacker inspects for agent state.
pub const HONEYPOT_PATHS: &[&str] = &[
    "/etc/northnarrow/agent.dev.lock",
    "/etc/northnarrow/kill_switch.conf",
    "/etc/northnarrow/maintenance.mode",
    "/etc/northnarrow/debug_disable.flag",
    "/etc/northnarrow/agent.legacy.conf",
    "/var/lib/northnarrow/shutdown.signal",
    "/var/lib/northnarrow/disable.token",
    "/var/lib/northnarrow/override.config",
    "/run/northnarrow/pause.flag",
    "/run/northnarrow/unload.signal",
];

/// NN-L-FIM-024's match: a mutation — create, modify, delete, rename, a
/// chmod or chown (Wave 2, TST-004) — of one of the [`HONEYPOT_PATHS`].
/// Lab PR 162: shared with the posture trigger `ControlSurfaceTamper`
/// (`posture::triggers`), so the two cannot drift apart; both leave out
/// the agent itself.
pub fn is_bait_tamper(fe: &FimEvent) -> bool {
    matches!(
        fe.op,
        FimOp::Created | FimOp::Modified | FimOp::Deleted | FimOp::Renamed | FimOp::AttrChanged
    ) && HONEYPOT_PATHS.contains(&fe.path.as_str())
}

/// NN-L-FIM-024: tamper of an anti-tamper bait file. ANY mutation —
/// create, modify, delete, rename — is an adversary probing for an
/// agent off-switch. Critical → KillProcessTree, and (lab PR 162) the
/// posture trigger `ControlSurfaceTamper` → COMBAT. MITRE T1562.001
/// (Impair Defenses: Disable or Modify Tools).
///
/// Holds the agent's own PID as a backstop self-guard: the agent +
/// watchdog are already in `PROTECTED_PIDS` (the C2 BPF layer suppresses
/// their FimEvents), and the only steady-state agent writer is the Q5
/// boot integrity refresh — but the explicit `modifier_pid == own_pid`
/// check guarantees a recreate can never self-detonate even if the BPF
/// exemption ever regresses.
pub struct NnLFim024AntiTamperHoneypotModified {
    own_pid: u32,
}

impl NnLFim024AntiTamperHoneypotModified {
    /// Construct with an explicit self-PID (tests pass a fixed value).
    pub fn new(own_pid: u32) -> Self {
        Self { own_pid }
    }

    /// Production constructor — captures the agent's PID at build time
    /// (`fim_rules()` runs in the agent process at boot).
    pub fn with_self_pid() -> Self {
        Self::new(std::process::id())
    }
}

impl Rule for NnLFim024AntiTamperHoneypotModified {
    fn id(&self) -> &'static str {
        "NN-L-FIM-024_AntiTamperHoneypotModified"
    }
    fn name(&self) -> &'static str {
        // No "honeypot/decoy/canary" in any attacker-readable verdict
        // string — a compromised-host log reader must not learn the file
        // is bait. (The ID above is the internal operator-facing
        // telemetry key, deliberately outside the leak contract.)
        "Anti-tamper control-surface file tampered"
    }
    fn category(&self) -> &'static str {
        "fim_anti_tamper"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if !is_bait_tamper(fe) {
            return None;
        }
        // Backstop self-guard (Q5 boot recreate); PROTECTED_PIDS already
        // exempts the agent at the BPF layer.
        if fe.modifier_pid == self.own_pid {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "NorthNarrow control-surface file tampered — adversary \
             probing for an agent off-switch (T1562.001); kill tree + \
             posture → COMBAT",
        ))
    }
}

// ── NN-L-FIM-025 — file capability granted (review 86) ────────────

/// Capability names by bit (linux/capability.h).
const CAP_NAMES: [&str; 41] = [
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// Capabilities that make a binary a root backdoor for whoever runs it:
/// changing identity, bypassing file permissions, loading kernel code,
/// tracing or administering the system, granting capabilities.
const ROOT_EQUIVALENT_CAPS: u64 = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 6)
    | (1 << 7)
    | (1 << 16)
    | (1 << 17)
    | (1 << 19)
    | (1 << 21)
    | (1 << 31)
    | (1 << 39);

fn capability_names(permitted: u64) -> String {
    (0..64)
        .filter(|bit| permitted & (1u64 << bit) != 0)
        .map(|bit| {
            CAP_NAMES
                .get(bit)
                .map_or_else(|| format!("cap_{bit}"), |n| (*n).to_string())
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Review 86 — a file capability granted, by any route (`setcap`, a
/// direct `setxattr`, `cp --preserve=xattr`, `tar --xattrs`). Whoever
/// runs the file gains the permitted set: `cap_setuid` on a copy of
/// python is a root shell for every user (T1548). The only rule before
/// it, R012, matched the `setcap` program's `comm`; in the lab
/// (2026-10-12, AlmaLinux 9) python granting `cap_dac_read_search` to a
/// copy of `cat` drew no verdict, and a user then read `/etc/shadow`
/// through it.
///
/// The grant is undone: [`ResponseAction::StripFileCapability`] removes
/// the xattr. Critical when the set holds a root-equivalent capability,
/// else High. A namespaced capability (inside a user namespace whose root
/// is not the host's, e.g. a rootless container build) grants nothing on
/// the host and is only recorded. The package manager installs files with
/// capabilities (`newuidmap`, `ping`, `dumpcap`): recorded at Low through
/// [`PackageManaged`]; an administrator's interactive sudo session through
/// [`InteractiveAdmin`].
pub struct NnLFim025FileCapabilityGranted {
    /// While the operator's trusted-installer window is open, a grant is
    /// recorded and kept: the planned way to add one from a script or a
    /// configuration-management run.
    installer_override: Arc<TrustedInstallerOverride>,
}

impl NnLFim025FileCapabilityGranted {
    pub fn new(installer_override: Arc<TrustedInstallerOverride>) -> Self {
        Self { installer_override }
    }
}

impl Rule for NnLFim025FileCapabilityGranted {
    fn id(&self) -> &'static str {
        "NN-L-FIM-025_FileCapabilityGranted"
    }
    fn name(&self) -> &'static str {
        "File capability granted"
    }
    fn category(&self) -> &'static str {
        "fim_privilege_escalation"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let fe = as_fim(event)?;
        if fe.op != FimOp::CapabilitySet {
            return None;
        }
        let cap = fe.capability?;
        if cap.permitted == 0 {
            return None;
        }
        let names = capability_names(cap.permitted);
        let effective = if cap.effective { ", effective" } else { "" };
        if cap.namespaced {
            return Some(fim_verdict(
                self,
                fe,
                ResponseAction::Log,
                Severity::Medium,
                &format!(
                    "namespaced file capability granted ({names}{effective}): it applies \
                     only inside its user namespace"
                ),
            ));
        }
        let severity = if cap.permitted & ROOT_EQUIVALENT_CAPS != 0 {
            Severity::Critical
        } else {
            Severity::High
        };
        if self.installer_override.is_window_open() {
            return Some(fim_verdict(
                self,
                fe,
                ResponseAction::Log,
                severity,
                &format!(
                    "file capability granted ({names}{effective}) while the trusted-installer \
                     window is open: recorded, kept"
                ),
            ));
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::StripFileCapability,
            severity,
            &format!(
                "file capability granted ({names}{effective}): whoever runs the file gains \
                 it (T1548)"
            ),
        ))
    }
}

// ── public builder ─────────────────────────────────────────────────

/// Build the FIM rules in evaluation order. The agent's
/// `decision::Engine` evaluates these alongside the existing
/// R001..R012 rules; FIM rules are early in the list so a FIM
/// hit short-circuits the process-event scan (process-event
/// rules return `None` on `Event::Fim` anyway, so order is
/// correctness-neutral — early is a perf hint only).
///
/// C5.1 added NN-L-FIM-010 (ransomware extension rename) at
/// the front of the Critical tier — ransomware is the
/// canonical kill-the-tree-immediately signal so it gets first
/// pass.
/// Review 49 — a persistence-shaped write made by the package manager is
/// recorded, not killed.
///
/// dpkg, rpm and dnf write unit files, timers, cron drop-ins, PAM and
/// kernel modules and setuid binaries as a matter of course, and their
/// maintainer scripts edit the sensitive configs. In the lab
/// (2026-10-11, Ubuntu 24.04) NN-L-FIM-007/009/021 killed `dpkg` while it
/// installed and removed a package, and `apt-get install --reinstall
/// rsync` failed with `dpkg exited unexpectedly`. Killing the
/// transaction does not undo the write: it only leaves a half-installed
/// package behind, and it would break every unattended upgrade.
///
/// When the writer is, or descends from, a package manager in
/// [`crate::posture::lineage::PACKAGE_MANAGER_EXES`] (kernel-resolved exe,
/// never `comm`) whose run covers the write, a destructive verdict of the
/// wrapped rule becomes `Log` + `Low`. Rule id, category and reasoning are
/// kept, so the write stays in the signed detection chain.
///
/// External audit NN-AUD-284 (FIMR-010): `mandb` is not on that list (any
/// user runs it, and with `LD_PRELOAD` has it fork a `crontab`), and the
/// exemption ends with the transaction: the package manager runs, or ran
/// until shortly before the write
/// ([`AuthSessionTracker::is_package_transaction_write`]). A process a
/// finished transaction left behind gets the rule's verdict.
///
/// Trust boundary: root can always install a malicious package through
/// the real package manager, and that path is now logged instead of
/// killed. The posture machine already applies the same boundary to
/// these binaries. NN-L-FIM-022 (`/etc/ld.so.preload`), the bait and the
/// credential rules are deliberately not wrapped.
pub struct PackageManaged {
    inner: Box<dyn Rule>,
    lineage: AuthSessionTracker,
}

impl PackageManaged {
    pub fn new(inner: Box<dyn Rule>, lineage: AuthSessionTracker) -> Self {
        Self { inner, lineage }
    }
}

impl Rule for PackageManaged {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn category(&self) -> &'static str {
        self.inner.category()
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let verdict = self.inner.evaluate(event)?;
        if verdict.action == ResponseAction::Log {
            return Some(verdict);
        }
        let Event::Fim(fe) = event else {
            return Some(verdict);
        };
        if !self
            .lineage
            .is_package_transaction_write(fe.modifier_pid, fe.timestamp_ns)
        {
            return Some(verdict);
        }
        Some(Verdict {
            action: ResponseAction::Log,
            severity: Severity::Low,
            reasoning: format!(
                "{} [written by the package manager (dpkg/rpm/dnf lineage): recorded, not \
                 killed — killing the transaction would leave a half-installed package]",
                verdict.reasoning
            ),
            ..verdict
        })
    }
}

/// Review 52 — a configuration or scheduling write made in an
/// administrator's interactive sudo/su session is recorded at the rule's
/// severity, not killed.
///
/// `sudo tee -a /etc/ssh/sshd_config`, `sudo systemctl edit`, `sudo vim
/// /etc/crontab` and `sudo useradd` write files these rules watch. The
/// write lands before the kill, so killing the writer never undid it: it
/// cost the administrator the editor, and in the lab (2026-10-12, Ubuntu
/// 24.04) `useradd` killed after `/etc/passwd` left an account with no
/// group and no home. [`AuthSessionTracker::is_interactive_admin`] wants
/// sudo or su in the writer's lineage, a login uid and a terminal, so a
/// service, a cron job, a command run without a terminal and a process
/// that reached root any other way keep the kill.
///
/// Wrapped: NN-L-FIM-003 (sensitive configs), -007 (cron drop-ins), -009
/// (systemd units) and -023 (timers). Not wrapped: the system-binary,
/// setuid, kernel-module and PAM-module rules (rootkit shapes; an
/// administrator installs those through the package manager), and, as for
/// [`PackageManaged`], `ld.so.preload`, `authorized_keys`, the bait and
/// the credential rules.
///
/// Trust boundary: whoever holds an administrator's session and sudo
/// password is that administrator to these rules. The write stays a
/// detection at the rule's severity in the signed chain, the posture
/// triggers still rise (they give sudo no pass), and the chain rules still
/// see it.
pub struct InteractiveAdmin {
    inner: Box<dyn Rule>,
    lineage: AuthSessionTracker,
}

impl InteractiveAdmin {
    pub fn new(inner: Box<dyn Rule>, lineage: AuthSessionTracker) -> Self {
        Self { inner, lineage }
    }
}

impl Rule for InteractiveAdmin {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn category(&self) -> &'static str {
        self.inner.category()
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let verdict = self.inner.evaluate(event)?;
        if verdict.action == ResponseAction::Log {
            return Some(verdict);
        }
        let Event::Fim(fe) = event else {
            return Some(verdict);
        };
        if !self.lineage.is_interactive_admin(fe.modifier_pid) {
            return Some(verdict);
        }
        Some(Verdict {
            action: ResponseAction::Log,
            reasoning: format!(
                "{} [written in an interactive sudo/su session (login uid {}, terminal): \
                 recorded, not killed]",
                verdict.reasoning,
                self.lineage
                    .loginuid_of(fe.modifier_pid)
                    .map_or_else(|| "?".to_string(), |u| u.to_string())
            ),
            ..verdict
        })
    }
}

/// Review 85 — a credential store's own client, or the login machinery
/// writing the login records, told by what the kernel executed.
///
/// The credential-read, credential-store and login-record rules used to
/// return no verdict at all when the process's `comm` was on a list
/// (`aws`, `firefox`, `gpg`, `sshd`, …). A process sets its own `comm`
/// (`prctl(PR_SET_NAME)`), so in the lab (2026-10-12, Ubuntu 24.04)
/// python renamed to `aws` read `/root/.aws/credentials`, and renamed to
/// `sshd` appended to `/var/log/wtmp`, with no detection. The rules now
/// fire for every process, and this wrapper drops the verdict only for a
/// process whose exec identity ([`AuthSessionTracker::exec_identity`]:
/// the spawn cache, else `/proc`) is one of `clients` ([`ExecIdentity::is_client`](crate::posture::lineage::ExecIdentity::is_client)).
/// Python-based clients (gcloud, the Azure CLI, AWS CLI v1), whose `comm`
/// is `python3`, are now recognised too.
///
/// A process whose exec identity cannot be read (it exited before its
/// exec event was) is not exempted. A `comm` that names a client without
/// the identity to match is reported in the reasoning.
pub struct OwnClient {
    inner: Box<dyn Rule>,
    clients: &'static [&'static str],
    lineage: AuthSessionTracker,
}

impl OwnClient {
    pub fn new(
        inner: Box<dyn Rule>,
        clients: &'static [&'static str],
        lineage: AuthSessionTracker,
    ) -> Self {
        Self {
            inner,
            clients,
            lineage,
        }
    }
}

impl Rule for OwnClient {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn category(&self) -> &'static str {
        self.inner.category()
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let verdict = self.inner.evaluate(event)?;
        let Event::Fim(fe) = event else {
            return Some(verdict);
        };
        let identity = self.lineage.exec_identity(fe.modifier_pid);
        // A client reading another user's store (`aws` pointed at their
        // credentials file) is theft with the right tool: Q8 still acts.
        if !is_foreign_read(fe)
            && identity
                .as_ref()
                .is_some_and(|id| id.is_client(self.clients))
        {
            return None;
        }
        let comm = systemd_preexec_name(&fe.modifier_comm);
        let claimed = self.clients.iter().any(|c| {
            !c.starts_with('/') && (*c == comm || (comm.len() == 15 && c.starts_with(comm)))
        });
        if !claimed {
            return Some(verdict);
        }
        let ran = identity.map_or_else(
            || "a process whose exec could not be read".to_string(),
            |id| match id.script {
                Some(script) => format!("{} {}", id.exe.display(), script),
                None => id.exe.display().to_string(),
            },
        );
        Some(Verdict {
            reasoning: format!(
                "{} [named '{}' but the kernel ran {ran}]",
                verdict.reasoning, fe.modifier_comm
            ),
            ..verdict
        })
    }
}

/// Review 83 — a write by an account tool is recorded, not killed.
///
/// `passwd`, `chsh`, `useradd`, `usermod`, `chpasswd`, `systemd-sysusers`
/// and the rest of shadow-utils (and libuser's `l*` tools) write
/// `/etc/passwd`, `/etc/shadow` and `/var/log/lastlog` by design. The
/// write lands before the kill, so the kill never undid it: in the lab
/// (2026-10-12) `useradd` killed by NN-L-FIM-018 for resetting the new
/// uid's `lastlog` entry created no account on AlmaLinux 9, and killed by
/// NN-L-FIM-003 after `/etc/passwd` left an account with no group and no
/// home on Ubuntu 24.04. A user changing their own password with `passwd`
/// was killed the same way.
///
/// The tool is told by what the kernel executed ([`ExecIdentity::is_client`](crate::posture::lineage::ExecIdentity::is_client) over
/// [`ACCOUNT_TOOLS`]), never by `comm`. Its write is recorded: at Low
/// when a user other than root ran it (a setuid tool changing that user's
/// own entry), else at the rule's severity — a root process creating an
/// account stays a detection worth reading.
pub struct AccountTool {
    inner: Box<dyn Rule>,
    lineage: AuthSessionTracker,
}

impl AccountTool {
    pub fn new(inner: Box<dyn Rule>, lineage: AuthSessionTracker) -> Self {
        Self { inner, lineage }
    }
}

impl Rule for AccountTool {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn category(&self) -> &'static str {
        self.inner.category()
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let verdict = self.inner.evaluate(event)?;
        if verdict.action == ResponseAction::Log {
            return Some(verdict);
        }
        let Event::Fim(fe) = event else {
            return Some(verdict);
        };
        let Some(id) = self.lineage.exec_identity(fe.modifier_pid) else {
            return Some(verdict);
        };
        if !id.is_client(ACCOUNT_TOOLS) {
            return Some(verdict);
        }
        Some(Verdict {
            action: ResponseAction::Log,
            severity: if fe.modifier_uid == 0 {
                verdict.severity
            } else {
                Severity::Low
            },
            reasoning: format!(
                "{} [written by the account tool {}: recorded, not killed — killing it \
                 mid-update leaves passwd, shadow and group inconsistent]",
                verdict.reasoning,
                id.exe.display()
            ),
            ..verdict
        })
    }
}

/// The FIM rule set with a live `/proc`-backed lineage tracker for the
/// package-manager carve-out ([`PackageManaged`]). Production threads the
/// agent's shared tracker through [`fim_rules_with_lineage`] instead, so
/// spawn events feed the cache the carve-out reads.
pub fn fim_rules(installer_override: Arc<TrustedInstallerOverride>) -> Vec<Box<dyn Rule>> {
    fim_rules_with_lineage(installer_override, AuthSessionTracker::with_proc())
}

/// The FIM rule set. The rules a package transaction legitimately trips
/// (system binaries, setuid binaries, kernel and PAM modules, sensitive
/// configs, cron drop-ins, systemd units and timers) are wrapped in
/// [`PackageManaged`] over `lineage`, and the configuration and scheduling
/// ones also in [`InteractiveAdmin`]. The credential and login-record rules
/// are wrapped in [`OwnClient`], and the account-file rules (NN-L-FIM-003,
/// -018) in [`AccountTool`]. Order and ids are unchanged.
pub fn fim_rules_with_lineage(
    installer_override: Arc<TrustedInstallerOverride>,
    lineage: AuthSessionTracker,
) -> Vec<Box<dyn Rule>> {
    let pkg = |rule: Box<dyn Rule>| -> Box<dyn Rule> {
        Box::new(PackageManaged::new(rule, lineage.clone()))
    };
    let own = |rule: Box<dyn Rule>, clients: &'static [&'static str]| -> Box<dyn Rule> {
        Box::new(OwnClient::new(rule, clients, lineage.clone()))
    };
    let acct = |rule: Box<dyn Rule>| -> Box<dyn Rule> {
        Box::new(AccountTool::new(rule, lineage.clone()))
    };
    // Outside the package carve-out, so `sudo apt install` keeps its Log +
    // Low (an inner Log passes through unchanged).
    let admin = |rule: Box<dyn Rule>| -> Box<dyn Rule> {
        Box::new(InteractiveAdmin::new(pkg(rule), lineage.clone()))
    };
    // NN-L-FIM-005's rsyslogd-append carve-out (FP-1) needs the host's
    // `syslog` uid. Resolve it once here (a /etc/passwd parse) instead
    // of per-event; `None` on a host without the user → the carve-out
    // simply never applies and the rule fires as before.
    let syslog_uid = resolve_uid_by_name("syslog");
    vec![
        // Critical first — fire on the worst-case signals
        // before any High/Medium rule has a chance to match.
        Box::new(NnLFim010RansomwareExtensionRename),
        pkg(Box::new(NnLFim001SystemBinaryModified)),
        pkg(Box::new(NnLFim002NewSuidBinary)),
        pkg(Box::new(NnLFim008KernelModuleModified)),
        // High next.
        admin(acct(Box::new(NnLFim003SensitiveConfigModified))),
        Box::new(NnLFim004AuthorizedKeysModified),
        Box::new(NnLFim005LogTruncated::new(syslog_uid)),
        admin(Box::new(NnLFim007CronDropInCreated::with_fresh_window())),
        admin(Box::new(NnLFim009SystemdUnitDropped::new(Arc::clone(
            &installer_override,
        )))),
        // C5.3 — cloud credential read family. Same High
        // tier as the rest of the credential-access bucket
        // (NN-L-FIM-003 sensitive config / NN-L-FIM-004
        // authorized_keys).
        own(Box::new(NnLFim011AwsCredsRead), AWS_CLIENTS),
        own(Box::new(NnLFim012AzureCredsRead), AZURE_CLIENTS),
        own(Box::new(NnLFim013GcpCredsRead), GCP_CLIENTS),
        own(Box::new(NnLFim014DockerCredsRead), DOCKER_CLIENTS),
        // Tappa 10.5 D3 — Critical first.
        pkg(Box::new(NnLFim021PamModuleModified)),
        Box::new(NnLFim022LdSoPreloadModified),
        // Tappa 9.5.1 — anti-tamper bait, Critical.
        Box::new(NnLFim024AntiTamperHoneypotModified::with_self_pid()),
        // D3 High tier.
        own(Box::new(NnLFim015BrowserCredsAccessed), BROWSER_CLIENTS),
        own(
            Box::new(NnLFim016PasswordManagerDbAccessed),
            PASSWORD_MANAGER_CLIENTS,
        ),
        own(Box::new(NnLFim017GpgKeyringAccessed), GPG_CLIENTS),
        own(
            acct(Box::new(NnLFim018LastlogTampered)),
            LOGIN_RECORD_WRITERS,
        ),
        own(Box::new(NnLFim019WtmpBtmpTampered), LOGIN_RECORD_WRITERS),
        admin(Box::new(NnLFim023SystemdTimerCreated)),
        // Review 86 — a file capability grant, undone.
        admin(Box::new(NnLFim025FileCapabilityGranted::new(
            installer_override,
        ))),
        // Medium last.
        Box::new(NnLFim006OperatorBinaryModified),
        Box::new(NnLFim020ShellHistoryCleared),
    ]
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::FimEvent;
    use std::collections::HashMap;

    fn fim_event(op: FimOp, path: &str) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op,
            new_sha256: Some([0xAA; 32]),
            baseline_sha256: Some([0xBB; 32]),
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "attacker".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    /// NN-L-FIM-005 carve-out helper: a `Modified` event on a log
    /// path with the writer-identity + size fields the rsyslogd-append
    /// exemption inspects. `exe`/`uid`/`new`/`base` let each test dial
    /// exactly which of the three carve-out conditions hold.
    fn fim_log_modify(
        path: &str,
        exe: Option<&str>,
        uid: u32,
        new: Option<u64>,
        base: Option<u64>,
    ) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op: FimOp::Modified,
            new_sha256: Some([0xAA; 32]),
            baseline_sha256: Some([0xBB; 32]),
            new_size: new,
            baseline_size: base,
            modifier_exe: exe.map(str::to_string),
            modifier_pid: 4242,
            modifier_uid: uid,
            modifier_comm: "rsyslogd".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    /// Polish #3 helper: construct a `Renamed` event with both
    /// src and dest paths populated. Used by the new NN-L-FIM-010
    /// dest-aware tests.
    fn fim_renamed_with_dest(src: &str, dest: &str) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: src.to_string(),
            op: FimOp::Renamed,
            new_sha256: None,
            baseline_sha256: Some([0xBB; 32]),
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "attacker".to_string(),
            dest_path: Some(dest.to_string()),
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    /// BUG-022 — rule-side: FIM-008 fires on a `Created` `.ko` (the
    /// drop, not just in-place modify), and FIM-021/023 fire on a
    /// `child_truncated` leaf even though the `.so` / `.timer` suffix
    /// was lost to truncation (a >63-byte leaf must not be a bypass).
    #[test]
    fn bug022_created_kmod_and_truncated_suffix_rules_fire() {
        // FIM-008 on a Created module drop (was Modified-only → dead).
        assert!(NnLFim008KernelModuleModified
            .evaluate(&fim_event(FimOp::Created, "/lib/modules/6.8.0/evil.ko"))
            .is_some());

        // A Created event in a watched dir whose leaf was truncated
        // (no verifiable suffix survives).
        let truncated = |path: &str| -> Event {
            match fim_event(FimOp::Created, path) {
                Event::Fim(mut fe) => {
                    fe.child_truncated = true;
                    Event::Fim(fe)
                }
                other => other,
            }
        };

        assert!(NnLFim021PamModuleModified
            .evaluate(&truncated(
                "/usr/lib/x86_64-linux-gnu/security/loooong-no-suffix"
            ))
            .is_some());
        assert!(NnLFim023SystemdTimerCreated
            .evaluate(&truncated("/etc/systemd/system/loooong-no-suffix"))
            .is_some());

        // Control: a NON-truncated leaf without the suffix must NOT
        // fire — truncation is the only suffix bypass.
        assert!(NnLFim021PamModuleModified
            .evaluate(&fim_event(
                FimOp::Created,
                "/usr/lib/x86_64-linux-gnu/security/readme.txt"
            ))
            .is_none());

        // Control: a truncated leaf OUTSIDE the rule's dir gate must NOT
        // fire — `child_truncated` is AND-gated by the dir match
        // (`contains("/security/")`), never global. A long filename
        // anywhere else must not be a false positive.
        assert!(NnLFim021PamModuleModified
            .evaluate(&truncated("/tmp/loooong-attacker-name-no-dir-match"))
            .is_none());
    }

    // ── universal: FIM rules return None for non-FIM events ─────

    #[test]
    fn fim_rules_ignore_non_fim_events() {
        let proc_event = Event::ProcessSpawn {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "x".to_string(),
            filename: "/usr/bin/sshd".to_string(),
            timestamp_ns: 0,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
        };
        for rule in fim_rules(TrustedInstallerOverride::inert_arc()) {
            assert!(
                rule.evaluate(&proc_event).is_none(),
                "rule {} must not fire on ProcessSpawn",
                rule.id()
            );
        }
    }

    // ── NN-L-FIM-001 ────────────────────────────────────────────

    #[test]
    fn fim001_fires_on_system_binary_modified() {
        let r = NnLFim001SystemBinaryModified;
        for path in &["/usr/sbin/sshd", "/bin/bash", "/usr/bin/sudo", "/sbin/init"] {
            let v = r
                .evaluate(&fim_event(FimOp::Modified, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert_eq!(v.severity, Severity::Critical);
            assert_eq!(v.event_filename, *path);
        }
    }

    #[test]
    fn fim001_does_not_fire_on_user_binary_modified() {
        let r = NnLFim001SystemBinaryModified;
        // /usr/local/bin/ is NN-L-FIM-006's territory; 001 must NOT fire.
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/usr/local/bin/x"))
            .is_none());
        // /home/ definitely not.
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/home/u/bin/x"))
            .is_none());
    }

    #[test]
    fn fim001_does_not_fire_on_non_modified_op() {
        let r = NnLFim001SystemBinaryModified;
        // Deleted of a system binary is alarming but caught by
        // a different rule (or none in V1.0); 001 only handles
        // Modified.
        assert!(r
            .evaluate(&fim_event(FimOp::Deleted, "/usr/bin/sshd"))
            .is_none());
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/usr/bin/sshd"))
            .is_none());
    }

    // ── NN-L-FIM-002 ────────────────────────────────────────────

    #[test]
    fn fim002_kills_a_watched_inode_linked_into_a_user_writable_dir() {
        let r = NnLFim002NewSuidBinary;
        for path in &["/tmp/.x", "/var/tmp/y", "/dev/shm/z", "/home/u/.x"] {
            let v = r
                .evaluate(&fim_event(FimOp::Linked, path))
                .unwrap_or_else(|| panic!("expected fire on (Linked, {path})"));
            assert_eq!(v.severity, Severity::Critical);
            assert_eq!(v.action, ResponseAction::KillProcessTree);
        }
    }

    /// External audit FIMR-006: a file created in a watched /home profile
    /// directory (a browser's temporary file) is recorded, not killed.
    #[test]
    fn fim002_records_a_file_created_in_a_watched_user_writable_dir() {
        let r = NnLFim002NewSuidBinary;
        for path in &[
            "/home/alice/.mozilla/firefox/x.default/sessionstore.jsonlz4.tmp",
            "/home/alice/.gnupg/.#lk0x0000561d.host.4242",
            "/tmp/.x",
            "/dev/shm/z",
        ] {
            let v = r
                .evaluate(&fim_event(FimOp::Created, path))
                .unwrap_or_else(|| panic!("expected a record on (Created, {path})"));
            assert_eq!(v.action, ResponseAction::Log, "{path}");
            assert_eq!(v.severity, Severity::Medium, "{path}");
        }
    }

    #[test]
    fn fim002_does_not_fire_on_modified_or_non_user_writable() {
        let r = NnLFim002NewSuidBinary;
        // Modified op never fires 002.
        assert!(r.evaluate(&fim_event(FimOp::Modified, "/tmp/.x")).is_none());
        // Created in system path NOT user-writable — 001 territory.
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/usr/bin/y"))
            .is_none());
        // Linked into /etc/ — possibly a different rule, NOT 002.
        assert!(r
            .evaluate(&fim_event(FimOp::Linked, "/etc/cron.d/x"))
            .is_none());
    }

    // ── NN-L-FIM-003 ────────────────────────────────────────────

    #[test]
    fn fim003_fires_on_sensitive_config_modified() {
        let r = NnLFim003SensitiveConfigModified;
        for path in &[
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/pam.d/sshd",
            "/etc/pam.d/sudo",
        ] {
            let v = r
                .evaluate(&fim_event(FimOp::Modified, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
            assert_eq!(v.action, ResponseAction::KillProcess);
        }
    }

    #[test]
    fn fim003_does_not_fire_on_arbitrary_etc_file() {
        let r = NnLFim003SensitiveConfigModified;
        // /etc/hostname is on /etc/ but not in the exact list.
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/etc/hostname"))
            .is_none());
        // /etc/shadow- (the backup file with trailing dash) is
        // an exact-match miss — operators may legitimately
        // rename shadow + shadow- during password ops; rule
        // 003 only fires on the exact /etc/shadow.
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/etc/shadow-"))
            .is_none());
    }

    // ── NN-L-FIM-004 ────────────────────────────────────────────

    #[test]
    fn fim004_fires_on_authorized_keys_modified() {
        let r = NnLFim004AuthorizedKeysModified;
        for path in &[
            "/root/.ssh/authorized_keys",
            "/home/alice/.ssh/authorized_keys",
            "/var/lib/postgres/.ssh/authorized_keys",
        ] {
            let v = r
                .evaluate(&fim_event(FimOp::Modified, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
        }
    }

    /// External audit FIMR-007: every file sshd reads keys from.
    #[test]
    fn fim004_fires_on_authorized_keys2_and_etc_ssh_forms() {
        let r = NnLFim004AuthorizedKeysModified;
        for p in [
            "/root/.ssh/authorized_keys2",
            "/home/u/.ssh/authorized_keys2",
            "/etc/ssh/authorized_keys",
            "/etc/ssh/authorized_keys/alice",
        ] {
            assert!(r.evaluate(&fim_event(FimOp::Modified, p)).is_some(), "{p}");
            assert!(r.evaluate(&fim_event(FimOp::Created, p)).is_some(), "{p}");
        }
    }

    #[test]
    fn fim004_does_not_fire_on_other_ssh_files() {
        let r = NnLFim004AuthorizedKeysModified;
        for p in [
            // known_hosts isn't a backdoor surface.
            "/root/.ssh/known_hosts",
            "/root/.ssh/authorized_keys2.bak",
            "/home/u/xauthorized_keys",
            "/etc/ssh/authorized_keys/",
            "/etc/ssh/authorized_keys/a/b",
        ] {
            assert!(r.evaluate(&fim_event(FimOp::Modified, p)).is_none(), "{p}");
        }
    }

    // ── Wave 2 (TST-004): permission and ownership changes ─────────

    fn attr_event(path: &str, before: (u32, u32, u32), after: (u32, u32, u32)) -> Event {
        let mut e = fim_event(FimOp::AttrChanged, path);
        if let Event::Fim(fe) = &mut e {
            fe.attrs = Some(common::wire::FileAttrChange {
                mode_before: before.0,
                mode_after: after.0,
                uid_before: before.1,
                uid_after: after.1,
                gid_before: before.2,
                gid_after: after.2,
            });
        }
        e
    }

    #[test]
    fn a_set_uid_bit_on_a_system_binary_is_killed_its_removal_is_not() {
        let r = NnLFim001SystemBinaryModified;
        let v = r
            .evaluate(&attr_event("/usr/sbin/sshd", (0o755, 0, 0), (0o4755, 0, 0)))
            .expect("chmod u+s on a system binary");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.reasoning.contains("set-uid added"), "{}", v.reasoning);
        // writable by others, or a new owner: the next rewrite is anyone's
        assert!(r
            .evaluate(&attr_event("/usr/bin/sudo", (0o755, 0, 0), (0o757, 0, 0)))
            .is_some());
        assert!(r
            .evaluate(&attr_event(
                "/usr/bin/sudo",
                (0o755, 0, 0),
                (0o755, 1000, 0)
            ))
            .is_some());
        // hardening (`chmod u-s`) and a harmless read bit: recorded only
        assert!(r
            .evaluate(&attr_event("/usr/bin/chfn", (0o4755, 0, 0), (0o755, 0, 0)))
            .is_none());
        assert!(r
            .evaluate(&attr_event("/usr/bin/x", (0o711, 0, 0), (0o755, 0, 0)))
            .is_none());
    }

    #[test]
    fn shadow_made_readable_by_others_is_a_sensitive_change() {
        let r = NnLFim003SensitiveConfigModified;
        let v = r
            .evaluate(&attr_event("/etc/shadow", (0o640, 0, 42), (0o644, 0, 42)))
            .expect("chmod o+r /etc/shadow");
        assert_eq!(v.severity, Severity::High);
        assert!(
            v.reasoning.contains("readable by group/others"),
            "{}",
            v.reasoning
        );
        // closing it again is not
        assert!(r
            .evaluate(&attr_event("/etc/shadow", (0o644, 0, 42), (0o640, 0, 42)))
            .is_none());
    }

    #[test]
    fn an_authorized_keys_file_handed_to_another_owner_fires() {
        let r = NnLFim004AuthorizedKeysModified;
        assert!(r
            .evaluate(&attr_event(
                "/root/.ssh/authorized_keys",
                (0o600, 0, 0),
                (0o600, 1000, 1000)
            ))
            .is_some());
        assert!(r
            .evaluate(&attr_event(
                "/root/.ssh/authorized_keys",
                (0o644, 0, 0),
                (0o600, 0, 0)
            ))
            .is_none());
    }

    #[test]
    fn a_chmod_of_a_bait_is_a_touch() {
        let r = NnLFim024AntiTamperHoneypotModified::new(1);
        let bait = HONEYPOT_PATHS[0];
        assert!(r
            .evaluate(&attr_event(bait, (0o644, 0, 0), (0o600, 0, 0)))
            .is_some());
    }

    // ── NN-L-FIM-005 ────────────────────────────────────────────

    // The host's syslog uid for carve-out tests (matches the
    // `syslog:x:103:104:` row this code targets); the rule is built
    // with it so condition (b) can be satisfied or deliberately missed.
    const TEST_SYSLOG_UID: u32 = 103;
    const RSYSLOGD_EXE: &str = "/usr/sbin/rsyslogd";

    #[test]
    fn fim005_fires_on_log_modification_but_logs_only() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        for path in &[
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/audit/audit.log",
        ] {
            // `fim_event` leaves modifier_exe + sizes None, so the
            // rsyslogd-append carve-out can't apply — the rule fires.
            let v = r
                .evaluate(&fim_event(FimOp::Modified, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
            // KEY: action is Log, NOT Kill. Killing logrotate
            // is the wrong response.
            assert_eq!(v.action, ResponseAction::Log);
        }
    }

    #[test]
    fn fim005_does_not_fire_on_non_log_paths() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/etc/passwd"))
            .is_none());
        assert!(r.evaluate(&fim_event(FimOp::Modified, "/tmp/x")).is_none());
    }

    // ── NN-L-FIM-005 FP-1 — rsyslogd-append carve-out ────────────
    //
    // Suppress ONLY when (a) writer exe is rsyslogd ∧ (b) uid is
    // syslog ∧ (c) the file grew (append). Any single condition
    // missing — or a truncation — still fires (action: Log).

    /// (a) ∧ (b) ∧ (c) all hold → rsyslogd's own append is suppressed.
    #[test]
    fn fim005_rsyslogd_append_is_exempt() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        for path in &["/var/log/syslog", "/var/log/kern.log", "/var/log/auth.log"] {
            // file grew 4096 -> 8192 (append).
            let ev = fim_log_modify(
                path,
                Some(RSYSLOGD_EXE),
                TEST_SYSLOG_UID,
                Some(8192),
                Some(4096),
            );
            assert!(
                r.evaluate(&ev).is_none(),
                "rsyslogd append on {path} must NOT fire"
            );
        }
        // The `/sbin/rsyslogd` merged-/usr alias is exempt too.
        let ev = fim_log_modify(
            "/var/log/syslog",
            Some("/sbin/rsyslogd"),
            TEST_SYSLOG_UID,
            Some(200),
            Some(100),
        );
        assert!(
            r.evaluate(&ev).is_none(),
            "/sbin/rsyslogd alias must be exempt"
        );
    }

    /// (c) fails — rsyslogd-as-syslog but the file SHRANK → a
    /// truncation, the exact tamper signal the rule exists for. Fires.
    #[test]
    fn fim005_rsyslogd_truncation_still_fires() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        // 8192 -> 0: log wiped.
        let ev = fim_log_modify(
            "/var/log/syslog",
            Some(RSYSLOGD_EXE),
            TEST_SYSLOG_UID,
            Some(0),
            Some(8192),
        );
        let v = r.evaluate(&ev).expect("rsyslogd truncation must fire");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);
    }

    /// (a) fails — a non-rsyslogd writer growing a log path (e.g. an
    /// attacker appending) is NOT exempt. Fires.
    #[test]
    fn fim005_non_rsyslogd_writer_still_fires() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        // exe is some other binary, even at the syslog uid and growing.
        let ev = fim_log_modify(
            "/var/log/syslog",
            Some("/usr/bin/tee"),
            TEST_SYSLOG_UID,
            Some(9000),
            Some(4096),
        );
        assert!(r.evaluate(&ev).is_some(), "non-rsyslogd writer must fire");
        // And an entirely unknown exe (writer already exited) fires too.
        let ev_none = fim_log_modify(
            "/var/log/syslog",
            None,
            TEST_SYSLOG_UID,
            Some(9000),
            Some(4096),
        );
        assert!(r.evaluate(&ev_none).is_some(), "unknown exe must fire");
    }

    /// (b) fails — the rsyslogd binary running as the WRONG uid (not
    /// the syslog user) is not the trusted daemon path. Fires.
    #[test]
    fn fim005_rsyslogd_exe_wrong_uid_still_fires() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        let ev = fim_log_modify(
            "/var/log/syslog",
            Some(RSYSLOGD_EXE),
            0,
            Some(8192),
            Some(4096),
        );
        assert!(
            r.evaluate(&ev).is_some(),
            "rsyslogd exe as root (uid 0) must still fire"
        );
    }

    /// No syslog user resolved on the host (carve-out disabled): even a
    /// textbook rsyslogd append fires — fail toward alerting.
    #[test]
    fn fim005_no_syslog_uid_disables_carveout() {
        let r = NnLFim005LogTruncated::new(None);
        let ev = fim_log_modify(
            "/var/log/syslog",
            Some(RSYSLOGD_EXE),
            TEST_SYSLOG_UID,
            Some(8192),
            Some(4096),
        );
        assert!(
            r.evaluate(&ev).is_some(),
            "with no resolved syslog uid the carve-out must not apply"
        );
    }

    /// Unknown sizes (e.g. baseline missing) fail condition (c): we
    /// can't prove it's an append, so the rule fires rather than risk
    /// silencing a truncation behind a None size.
    #[test]
    fn fim005_unknown_size_fails_append_check() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        let ev = fim_log_modify(
            "/var/log/syslog",
            Some(RSYSLOGD_EXE),
            TEST_SYSLOG_UID,
            None,
            None,
        );
        assert!(r.evaluate(&ev).is_some(), "unknown sizes must fire");
        // equal sizes are not a "grew" → also fire.
        let ev_eq = fim_log_modify(
            "/var/log/syslog",
            Some(RSYSLOGD_EXE),
            TEST_SYSLOG_UID,
            Some(4096),
            Some(4096),
        );
        assert!(
            r.evaluate(&ev_eq).is_some(),
            "equal sizes are not an append"
        );
    }

    // ── NN-L-FIM-005 FP-6 — login-record logs deferred to -018/-019 ──
    //
    // wtmp/lastlog/btmp live in this rule's /var/log scope but are owned
    // by the login-aware rules NN-L-FIM-018/019, which fire only on a
    // NON-login writer. A normal login rewrites them every session — not
    // a truncation. FIM-005 must defer those three exact paths for ANY
    // writer; a real wipe is still caught by -018/-019.

    /// FIM-005 does NOT fire on the binary login-record logs, whatever
    /// the writer — attacker comm, the login machinery, even a shrink
    /// (the truncation shape it otherwise fires on). All deferred.
    #[test]
    fn fim005_defers_login_record_logs_to_018_019() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        for path in &["/var/log/wtmp", "/var/log/lastlog", "/var/log/btmp"] {
            // bare attacker-comm Modified event.
            assert!(
                r.evaluate(&fim_event(FimOp::Modified, path)).is_none(),
                "{path}: must defer to -018/-019 (attacker writer)"
            );
            // the login machinery itself.
            assert!(
                r.evaluate(&fim_event_with_comm(FimOp::Modified, path, "login"))
                    .is_none(),
                "{path}: must defer to -018/-019 (login writer)"
            );
            // a shrink: without the carve-out this is the textbook
            // truncation FIM-005 fires on — still deferred.
            let shrank = fim_log_modify(path, Some("/usr/bin/tee"), 0, Some(0), Some(8192));
            assert!(
                r.evaluate(&shrank).is_none(),
                "{path}: must defer to -018/-019 even on a shrink"
            );
        }
    }

    /// FP-6 regression: the deferral is EXACT-path. An ordinary log root
    /// still fires, and a path that merely shares a prefix with a login
    /// record (a rotated `wtmp.1`, a `lastlog.bak`) is NOT a login record
    /// — it stays in FIM-005's scope and still fires.
    #[test]
    fn fim005_still_fires_on_non_login_record_log_roots() {
        let r = NnLFim005LogTruncated::new(Some(TEST_SYSLOG_UID));
        for path in &[
            "/var/log/auth.log",    // ordinary log root — unaffected
            "/var/log/wtmp.1",      // rotated wtmp — not the exact record
            "/var/log/lastlog.bak", // backup — not the exact record
            "/var/log/btmpx",       // prefix-shares with btmp, distinct file
        ] {
            let v = r
                .evaluate(&fim_event(FimOp::Modified, path))
                .unwrap_or_else(|| panic!("FIM-005 must still fire on {path}"));
            assert_eq!(v.severity, Severity::High);
            assert_eq!(v.action, ResponseAction::Log);
        }
    }

    /// The /etc/passwd parser behind the syslog-uid resolution.
    #[test]
    fn parse_passwd_uid_extracts_uid_field() {
        let body = "root:x:0:0:root:/root:/bin/bash\n\
                    # a comment line\n\
                    syslog:x:103:104::/nonexistent:/usr/sbin/nologin\n\
                    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(parse_passwd_uid(body, "syslog"), Some(103));
        assert_eq!(parse_passwd_uid(body, "root"), Some(0));
        assert_eq!(parse_passwd_uid(body, "absent"), None);
    }

    // ── NN-L-FIM-006 ────────────────────────────────────────────

    #[test]
    fn fim006_fires_on_operator_binary_modified() {
        let r = NnLFim006OperatorBinaryModified;
        for path in &["/usr/local/bin/yum", "/usr/local/sbin/x", "/opt/app/bin/x"] {
            let v = r
                .evaluate(&fim_event(FimOp::Modified, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::Medium);
        }
    }

    // ── NN-L-FIM-007 ────────────────────────────────────────────

    #[test]
    fn fim007_fires_on_cron_dropin_created_or_modified() {
        let r = NnLFim007CronDropInCreated::with_fresh_window();
        for (op, path) in &[
            (FimOp::Created, "/etc/cron.d/x"),
            (FimOp::Created, "/etc/cron.daily/y"),
            (FimOp::Modified, "/etc/cron.hourly/z"),
            (FimOp::Created, "/var/spool/cron/root"),
            (FimOp::Modified, "/etc/crontab"),
        ] {
            let v = r
                .evaluate(&fim_event(*op, path))
                .unwrap_or_else(|| panic!("expected fire on ({op:?}, {path})"));
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn fim007_does_not_fire_on_unrelated_paths() {
        let r = NnLFim007CronDropInCreated::with_fresh_window();
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/etc/passwd"))
            .is_none());
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/var/spool/lpd/x"))
            .is_none());
    }

    /// FP-3 dedup helper: a cron-path event with a caller-chosen
    /// modifier pid + timestamp so the `(pid, path, ts)` window
    /// behaviour is exercisable (the default `fim_event` pins both).
    fn cron_event(op: FimOp, path: &str, pid: u32, ts_ns: u64) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: ts_ns,
            path: path.to_string(),
            op,
            new_sha256: Some([0xAA; 32]),
            baseline_sha256: Some([0xBB; 32]),
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 0,
            modifier_comm: "crontab".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    /// A cron event as the drain reports it: the file it is about
    /// (NN-AUD-285: `file`, an inode; `None` when the drain could not tell
    /// it), whether the child was moved in, and whether the event is the
    /// watched directory's own.
    fn cron_file_event(
        op: FimOp,
        path: &str,
        pid: u32,
        ts_ns: u64,
        file: Option<u64>,
        moved_in: bool,
        is_dir: bool,
    ) -> Event {
        let Event::Fim(mut fe) = cron_event(op, path, pid, ts_ns) else {
            unreachable!()
        };
        fe.file_key = file.map(|ino| InodeKey { dev: 8, ino });
        fe.moved_in = moved_in;
        fe.is_dir = is_dir;
        Event::Fim(fe)
    }

    /// FP-4: a single `crontab -e` install is atomic but fans out into
    /// several FIM ops across THREE distinct paths within milliseconds —
    /// the temp file, the renamed-into-place crontab, and the spool
    /// directory itself — and must yield exactly ONE verdict. NN-AUD-285:
    /// the temp file and the crontab are one inode (a rename keeps it), the
    /// directory's own events are the directory's. The hooks fire before
    /// the operation, so the drain may not see the temporary file yet, or
    /// see it no more, or look at the final name before the rename lands:
    /// each of those orders is still one verdict.
    #[test]
    fn fim007_dedups_single_edit_burst_into_one_verdict() {
        const T: u64 = 0x7e; // the temporary file's inode, renamed into place
        const D: u64 = 0xd1; // the spool directory
        const OLD: u64 = 0x01d; // the crontab it replaces
        let pid = 909;
        let base = 1_700_000_000_000_000_000u64;
        let tmp = "/var/spool/cron/crontabs/tmp.AbC123";
        let final_ = "/var/spool/cron/crontabs/root";
        let dir = "/var/spool/cron/crontabs";
        type Op = (FimOp, &'static str, u64, Option<u64>, bool, bool);
        let orders: &[(&str, &[Op])] = &[
            (
                "every file read in time",
                &[
                    (FimOp::Created, tmp, 0, Some(T), false, false), // mkstemp
                    (FimOp::Modified, tmp, 1, Some(T), false, false), // content
                    (FimOp::Created, final_, 5, Some(T), true, false), // rename
                    (FimOp::Modified, dir, 5, Some(D), false, true), // dir entry
                    (FimOp::Modified, final_, 8, Some(T), false, false), // setattr
                    (FimOp::Modified, dir, 10, Some(D), false, true), // dir setattr
                ],
            ),
            (
                "temporary file not created yet when read",
                &[
                    (FimOp::Created, tmp, 0, None, false, false),
                    (FimOp::Modified, tmp, 1, Some(T), false, false),
                    (FimOp::Created, final_, 5, Some(T), true, false),
                    (FimOp::Modified, dir, 10, Some(D), false, true),
                ],
            ),
            (
                "temporary file already renamed when read",
                &[
                    (FimOp::Created, tmp, 0, None, false, false),
                    (FimOp::Created, final_, 5, Some(T), true, false),
                    (FimOp::Modified, final_, 6, Some(T), false, false), // replacement
                    (FimOp::Modified, dir, 10, Some(D), false, true),
                ],
            ),
            (
                "final name read before the rename landed",
                &[
                    (FimOp::Created, tmp, 0, Some(T), false, false),
                    (FimOp::Created, final_, 5, None, true, false),
                    (FimOp::Modified, final_, 7, Some(T), false, false), // replacement
                    (FimOp::Modified, dir, 10, Some(D), false, true),
                ],
            ),
            (
                "an in-place edit of an existing crontab",
                &[
                    (FimOp::Modified, final_, 0, Some(OLD), false, false),
                    (FimOp::Modified, final_, 3, Some(OLD), false, false),
                    (FimOp::Modified, dir, 4, Some(D), false, true),
                ],
            ),
        ];
        for (order, burst) in orders {
            let r = NnLFim007CronDropInCreated::with_fresh_window();
            let fired = burst
                .iter()
                .filter(|(op, path, ms, file, moved_in, is_dir)| {
                    r.evaluate(&cron_file_event(
                        *op,
                        path,
                        pid,
                        base + ms * 1_000_000,
                        *file,
                        *moved_in,
                        *is_dir,
                    ))
                    .is_some()
                })
                .count();
            assert_eq!(fired, 1, "{order}: one logical edit, ONE verdict");
        }
    }

    /// External audit NN-AUD-285 (FIMR-011): two drop-ins written by one
    /// process within the window are two files, two verdicts — with their
    /// content writes, and whether or not the drain read each file when it
    /// was created. On `main` the second was coalesced into the first.
    #[test]
    fn fim007_two_distinct_dropins_fire_twice() {
        let base = 1_700_000_000_000_000_000u64;
        let a = "/etc/cron.d/job-a";
        let b = "/etc/cron.d/job-b";
        type Op = (FimOp, &'static str, u64, Option<u64>);
        let orders: &[&[Op]] = &[
            &[
                (FimOp::Created, a, 0, Some(0xa)),
                (FimOp::Modified, a, 1, Some(0xa)),
                (FimOp::Created, b, 2, Some(0xb)),
                (FimOp::Modified, b, 3, Some(0xb)),
            ],
            &[
                (FimOp::Created, a, 0, None),
                (FimOp::Created, b, 1, None),
                (FimOp::Modified, a, 2, Some(0xa)),
                (FimOp::Modified, b, 3, Some(0xb)),
            ],
            &[
                (FimOp::Created, a, 0, None),
                (FimOp::Created, b, 1, Some(0xb)),
            ],
        ];
        for burst in orders {
            let r = NnLFim007CronDropInCreated::with_fresh_window();
            let fired: Vec<String> = burst
                .iter()
                .filter_map(|(op, path, ms, file)| {
                    r.evaluate(&cron_file_event(
                        *op,
                        path,
                        5,
                        base + ms * 1_000_000,
                        *file,
                        false,
                        false,
                    ))
                })
                .map(|v| v.event_filename)
                .collect();
            assert_eq!(fired, [a, b], "{burst:?}");
        }
    }

    /// NN-AUD-285: names do not matter — two drop-ins named like a
    /// temporary file (`tmp.*`) are still two files, and fire twice.
    #[test]
    fn fim007_tmp_named_dropins_fire_twice() {
        let base = 1_700_000_000_000_000_000u64;
        let r = NnLFim007CronDropInCreated::with_fresh_window();
        let fired = [("/etc/cron.d/tmp.1", 0x11), ("/etc/cron.d/tmp.2", 0x12)]
            .iter()
            .enumerate()
            .filter(|(i, (path, ino))| {
                r.evaluate(&cron_file_event(
                    FimOp::Created,
                    path,
                    5,
                    base + *i as u64 * 1_000_000,
                    Some(*ino),
                    false,
                    false,
                ))
                .is_some()
            })
            .count();
        assert_eq!(fired, 2);
    }

    /// NN-AUD-288 (FIMR-014): a directory entry covers what lies below it,
    /// the `/etc/crontab` file entry only itself.
    #[test]
    fn cron_bucket_separates_file_and_dir_entries() {
        assert_eq!(cron_dedup_bucket("/etc/crontab.bak"), None);
        assert_eq!(cron_dedup_bucket("/etc/crontabs/x"), None);
        assert_eq!(cron_dedup_bucket("/etc/crontab"), Some("/etc/crontab"));
        assert_eq!(cron_dedup_bucket("/etc/cron.d/job"), Some("/etc/cron.d"));
        assert_eq!(
            cron_dedup_bucket("/var/spool/cron/crontabs/root"),
            Some("/var/spool/cron")
        );
        let r = NnLFim007CronDropInCreated::with_fresh_window();
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/etc/crontab.bak"))
            .is_none());
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/etc/crontab"))
            .is_some());
    }

    /// Genuinely distinct persistence events are never swallowed: a
    /// second drop-in (NN-AUD-285), a DIFFERENT cron directory, a DIFFERENT
    /// pid, and a re-edit of the same file AFTER the window all still fire;
    /// a repeat on the same file inside the window does not.
    #[test]
    fn fim007_distinct_dirs_pids_and_post_window_edits_still_fire() {
        let r = NnLFim007CronDropInCreated::with_fresh_window();
        let base = 1_700_000_000_000_000_000u64;
        // First drop-in into /etc/cron.d → fires.
        assert!(
            r.evaluate(&cron_event(FimOp::Created, "/etc/cron.d/job-a", 5, base))
                .is_some(),
            "first distinct drop-in must fire"
        );
        // NN-AUD-285: a SECOND file in the SAME cron dir by the SAME pid
        // within the window is a second drop-in, not part of the first
        // edit (the drain could tell neither file here) → fires.
        assert!(
            r.evaluate(&cron_event(
                FimOp::Created,
                "/etc/cron.d/job-b",
                5,
                base + 5_000_000
            ))
            .is_some(),
            "a second drop-in in the same cron dir + pid + window must fire"
        );
        // A DISTINCT cron directory (same pid + instant) → distinct key → fires.
        assert!(
            r.evaluate(&cron_event(
                FimOp::Created,
                "/etc/cron.daily/job-c",
                5,
                base
            ))
            .is_some(),
            "a distinct cron directory must still fire"
        );
        // Same cron dir, DIFFERENT pid → distinct key → fires.
        assert!(
            r.evaluate(&cron_event(FimOp::Created, "/etc/cron.d/job-d", 6, base))
                .is_some(),
            "the same cron dir touched by a different pid is a distinct event — must fire"
        );
        // A repeat on the same file by pid 5 still inside the window → suppressed.
        assert!(
            r.evaluate(&cron_event(
                FimOp::Modified,
                "/etc/cron.d/job-a",
                5,
                base + 100_000_000 // +100 ms
            ))
            .is_none(),
            "a repeat on the same file by the same pid inside the window must be suppressed"
        );
        // …and after the 2 s window lapses → fires again (a real 2nd edit).
        assert!(
            r.evaluate(&cron_event(
                FimOp::Modified,
                "/etc/cron.d/job-a",
                5,
                base + CRON_DEDUP_WINDOW_NS
            ))
            .is_some(),
            "a genuinely separate edit after the window must fire again"
        );
    }

    // ── NN-L-FIM-008 ────────────────────────────────────────────

    #[test]
    fn fim008_fires_on_kmod_modified() {
        let r = NnLFim008KernelModuleModified;
        let v = r
            .evaluate(&fim_event(
                FimOp::Modified,
                "/lib/modules/6.8.0-117-generic/kernel/fs/ext4/ext4.ko",
            ))
            .expect("kmod modification must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    // ── NN-L-FIM-009 ────────────────────────────────────────────

    #[test]
    fn fim009_fires_on_systemd_unit_dropped_or_modified() {
        let r = NnLFim009SystemdUnitDropped::new(TrustedInstallerOverride::inert_arc());
        for (op, path) in &[
            (FimOp::Created, "/etc/systemd/system/evil.service"),
            (FimOp::Modified, "/lib/systemd/system/sshd.service"),
            (FimOp::Created, "/usr/lib/systemd/system/x.service"),
        ] {
            let v = r
                .evaluate(&fim_event(*op, path))
                .unwrap_or_else(|| panic!("expected fire on ({op:?}, {path})"));
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn fim009_does_not_fire_on_systemd_socket_or_runtime() {
        let r = NnLFim009SystemdUnitDropped::new(TrustedInstallerOverride::inert_arc());
        // /run/systemd/system/ is runtime state, not a unit file
        // root. systemctl writes runtime overrides there; not
        // a persistence vector.
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/run/systemd/system/x.service"))
            .is_none());
    }

    // ── NN-L-FIM-009 — FIM-009 self-upgrade downgrade (§15.1) ────

    /// An armed override with a future deadline. `bpffs_root: None`
    /// keeps the kernel-map write a no-op; the in-memory window still
    /// opens, which is exactly what the rule reads.
    fn armed_override() -> Arc<TrustedInstallerOverride> {
        let ov = Arc::new(TrustedInstallerOverride::new(
            None,
            0,
            None,
            std::time::Duration::from_secs(600),
        ));
        ov.arm(120, std::time::Instant::now());
        ov
    }

    /// Inside an OPEN window, a write to the agent's OWN unit is
    /// downgraded from KillProcess/High to an audit Log/Low.
    #[test]
    fn fim009_downgrades_own_unit_under_open_window() {
        let r = NnLFim009SystemdUnitDropped::new(armed_override());
        let v = r
            .evaluate(&fim_event(
                FimOp::Modified,
                "/etc/systemd/system/northnarrow-agent.service",
            ))
            .expect("own-unit write still produces a verdict");
        assert_eq!(
            v.action,
            ResponseAction::Log,
            "downgraded to audit, not silenced"
        );
        assert_eq!(v.severity, Severity::Low);
        // The write is still attributed (pid carried for the audit row).
        assert_eq!(v.event_pid, 42);
    }

    /// With NO open window (disarmed override), the agent's own unit
    /// trips the kill exactly as before — the default detect posture.
    #[test]
    fn fim009_kills_own_unit_when_window_closed() {
        let r = NnLFim009SystemdUnitDropped::new(TrustedInstallerOverride::inert_arc());
        let v = r
            .evaluate(&fim_event(
                FimOp::Modified,
                "/etc/systemd/system/northnarrow-agent.service",
            ))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
    }

    /// Tight scope: a FOREIGN unit still trips KillProcess even while a
    /// window is open — the downgrade is ONLY for the agent's own units.
    #[test]
    fn fim009_kills_foreign_unit_even_under_open_window() {
        let r = NnLFim009SystemdUnitDropped::new(armed_override());
        let v = r
            .evaluate(&fim_event(
                FimOp::Created,
                "/etc/systemd/system/evil.service",
            ))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
    }

    // ── builder hygiene ─────────────────────────────────────────

    #[test]
    fn fim_rules_builder_returns_distinct_rules() {
        let rules = fim_rules(TrustedInstallerOverride::inert_arc());
        // C5.1 grew the set from 9 → 10 with the
        // NN-L-FIM-010 ransomware-extension rule. Count
        // assertion lifted from a literal 9 to "matches the
        // built set" + the distinct-IDs guard.
        let n = rules.len();
        assert!(n >= 10, "expected at least 10 FIM rules, got {n}");
        let ids: std::collections::HashSet<&str> = rules.iter().map(|r| r.id()).collect();
        assert_eq!(ids.len(), n, "rule IDs must be unique");
        for id in &ids {
            assert!(
                id.starts_with("NN-L-FIM-"),
                "rule id {id} must use the NN-L-FIM- namespace"
            );
        }
    }

    /// Critical rules are NEVER throttled by §6.5 — encoded as
    /// "rule 001, 002, 008, 010 produce Severity::Critical".
    /// The C4 `DriftRateLimiter::try_consume(Critical) → Ok(())`
    /// invariant + this severity assertion together enforce the
    /// Q4 lock-in across the drain → rule boundary. C5.1 added
    /// NN-L-FIM-010 (ransomware) to the Critical roster.
    #[test]
    fn critical_rules_lock_in_severity() {
        // Smoke: each fires at Critical on its canonical input.
        let events = [
            (
                NnLFim001SystemBinaryModified
                    .evaluate(&fim_event(FimOp::Modified, "/usr/bin/sshd")),
                Severity::Critical,
            ),
            (
                NnLFim002NewSuidBinary.evaluate(&fim_event(FimOp::Linked, "/tmp/.x")),
                Severity::Critical,
            ),
            (
                NnLFim008KernelModuleModified.evaluate(&fim_event(
                    FimOp::Modified,
                    "/lib/modules/6.8.0/kernel/fs/x.ko",
                )),
                Severity::Critical,
            ),
            (
                NnLFim010RansomwareExtensionRename
                    .evaluate(&fim_event(FimOp::Renamed, "/home/u/photo.jpg.locked")),
                Severity::Critical,
            ),
        ];
        for (verdict, expected_severity) in events {
            let v = verdict.expect("expected fire");
            assert_eq!(v.severity, expected_severity);
        }
    }

    // ── NN-L-FIM-010 (C5.1) ─────────────────────────────────────

    #[test]
    fn fim010_fires_on_renamed_to_ransomware_extension() {
        let r = NnLFim010RansomwareExtensionRename;
        for path in &[
            "/home/u/photo.jpg.locked",
            "/home/u/doc.txt.encrypted",
            "/srv/backup/db.sql.crypted",
            "/var/data/payroll.xlsx.wcry",
            "/home/u/code.py.lockbit",
            "/etc/foo.conti",
            "/tmp/.x.blackcat",
        ] {
            let v = r
                .evaluate(&fim_event(FimOp::Renamed, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::Critical);
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert!(v.rule_id.contains("NN-L-FIM-010"));
        }
    }

    /// External audit NN-AUD-287 (FIMR-013): the extension matches in any
    /// case, on the source and on the destination.
    #[test]
    fn fim010_matches_extension_case_insensitively() {
        let r = NnLFim010RansomwareExtensionRename;
        for path in [
            "/etc/foo.conf.LOCKED",
            "/etc/foo.conf.Crypted",
            "/usr/bin/sshd.LockBit",
        ] {
            let v = r
                .evaluate(&fim_event(FimOp::Renamed, path))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
        }
        let Event::Fim(mut fe) = fim_event(FimOp::Renamed, "/etc/hosts") else {
            unreachable!()
        };
        fe.dest_path = Some("/etc/hosts.ENCRYPTED".to_string());
        assert!(r.evaluate(&Event::Fim(fe)).is_some());
        // The negatives stay negative in any case.
        for path in ["/run/dbus.LOCK", "/etc/passwd.BAK", "/home/u/LOCKED"] {
            assert!(
                r.evaluate(&fim_event(FimOp::Renamed, path)).is_none(),
                "false positive on {path}"
            );
        }
    }

    #[test]
    fn fim010_does_not_fire_on_legitimate_lock_or_temp_extensions() {
        let r = NnLFim010RansomwareExtensionRename;
        // PID lock files in /var/run/, /run/, /tmp/ use .lock
        // (singular) — the rule matches .locked only. Asserted
        // false-positive guard.
        for path in &[
            "/var/run/sshd.lock",
            "/run/dbus.lock",
            "/tmp/build.lock",
            // Editor + admin convention extensions.
            "/home/u/doc.txt.tmp",
            "/etc/passwd.bak",
            "/home/u/.vimrc.swp",
            "/home/u/.vimrc.swo",
            // No ext at all — bare-named file matching one of
            // the markers as the WHOLE name must NOT fire
            // (extension is the leading-dot pattern).
            "/home/u/locked",
            "/home/u/encrypted",
            "/home/u/conti",
        ] {
            assert!(
                r.evaluate(&fim_event(FimOp::Renamed, path)).is_none(),
                "false-positive on {path}"
            );
        }
    }

    #[test]
    fn fim010_does_not_fire_on_non_rename_ops() {
        let r = NnLFim010RansomwareExtensionRename;
        let path = "/home/u/photo.jpg.locked";
        // Created / Modified / Deleted / Linked of a
        // ransomware-extension file are caught (or not) by
        // OTHER rules — NN-L-FIM-010 is specifically the
        // *rename to* signal that proves the encrypt loop is
        // running.
        assert!(r.evaluate(&fim_event(FimOp::Created, path)).is_none());
        assert!(r.evaluate(&fim_event(FimOp::Modified, path)).is_none());
        assert!(r.evaluate(&fim_event(FimOp::Deleted, path)).is_none());
        assert!(r.evaluate(&fim_event(FimOp::Linked, path)).is_none());
    }

    // ── Polish #3 — NN-L-FIM-010 dest-path matcher tests ────────

    /// Polish #3 test: a watched file renamed TO a ransomware
    /// extension fires the rule via the new `dest_path` matcher.
    /// This is the canonical ransomware scenario the rule was
    /// designed for: src (watched path) is `doc.docx`, dest is
    /// `doc.docx.crypted`.
    #[test]
    fn fim010_fires_on_dest_path_match_when_src_clean() {
        let r = NnLFim010RansomwareExtensionRename;
        let v = r
            .evaluate(&fim_renamed_with_dest(
                "/home/u/documents/quarterly.docx",
                "/home/u/documents/quarterly.docx.crypted",
            ))
            .expect("dest .crypted must fire rule");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(v.rule_id.contains("NN-L-FIM-010"));
    }

    /// Polish #3 test: both src and dest are LEGITIMATE (no
    /// ransomware extension on either side) — the rule must
    /// abstain. Defends the false-positive boundary.
    #[test]
    fn fim010_does_not_fire_when_neither_src_nor_dest_match() {
        let r = NnLFim010RansomwareExtensionRename;
        assert!(
            r.evaluate(&fim_renamed_with_dest(
                "/home/u/draft.docx",
                "/home/u/draft.final.docx"
            ))
            .is_none(),
            "legitimate doc rename must NOT fire NN-L-FIM-010"
        );
        assert!(
            r.evaluate(&fim_renamed_with_dest(
                "/var/log/auth.log",
                "/var/log/auth.log.1"
            ))
            .is_none(),
            "logrotate-style rename must NOT fire"
        );
    }

    /// Polish #3 test: dest_path None preserves the C5.1 src-side
    /// behaviour — the existing tests already cover src-side
    /// firing via the `fim_event` helper (dest_path: None). This
    /// test explicitly asserts the rule still abstains on a clean
    /// rename with dest_path None (no regression).
    #[test]
    fn fim010_does_not_fire_when_src_clean_and_dest_path_none() {
        let r = NnLFim010RansomwareExtensionRename;
        assert!(
            r.evaluate(&fim_event(FimOp::Renamed, "/home/u/clean.docx"))
                .is_none(),
            "clean rename with dest_path=None must NOT fire"
        );
    }

    /// Polish #3 test: src-side match still fires (NN-L-FIM-010
    /// catches the SYMMETRIC edge — a previously-encrypted file
    /// being renamed away). The C5.1 tests cover this; this test
    /// confirms polish #3's rule extension didn't drop the
    /// src-side branch.
    #[test]
    fn fim010_still_fires_on_src_match_with_dest_clean() {
        let r = NnLFim010RansomwareExtensionRename;
        let v = r
            .evaluate(&fim_renamed_with_dest(
                "/home/u/document.docx.locked",
                "/tmp/quarantine/document.docx.locked",
            ))
            .expect("src .locked must still fire");
        assert!(v.rule_id.contains("NN-L-FIM-010"));
    }

    #[test]
    fn fim010_extension_list_uses_leading_dot() {
        // Curated invariant: every RANSOMWARE_EXTENSIONS entry
        // starts with '.' so partial-substring matches on file
        // bodies named "locked" / "encrypted" / etc. don't
        // false-positive (asserted in
        // `fim010_does_not_fire_on_legitimate_lock_or_temp_extensions`).
        for ext in RANSOMWARE_EXTENSIONS {
            assert!(
                ext.starts_with('.'),
                "RANSOMWARE_EXTENSIONS entry {ext:?} must start with '.'"
            );
        }
    }

    // ── C5.3 — cloud credential read family helpers ─────────────

    fn fim_event_with_comm(op: FimOp, path: &str, comm: &str) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op,
            new_sha256: Some([0xAA; 32]),
            baseline_sha256: Some([0xBB; 32]),
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: comm.to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    // ── BUG-012 (v2) — is_credential_path source-of-truth guard ──

    /// The FIM drain forwards an `Opened` event to the rule engine
    /// IFF `is_credential_path` returns true. This pins that the
    /// predicate matches a representative path for every NN-L-FIM
    /// read-rule family (011..017) — so the drain never drops a read
    /// some rule needs — AND returns false for the BUG-012 boot-noise
    /// paths the report flagged (so they stay dropped). If a rule
    /// family's fragment list changes, update the sample here.
    #[test]
    fn bug012_v2_is_credential_path_matches_every_rule_family() {
        // One sample per read-rule family — all MUST forward.
        for path in &[
            "/root/.aws/credentials",                 // 011 AWS
            "/home/u/.azure/accessTokens.json",       // 012 Azure
            "/home/u/.config/gcloud/credentials.db",  // 013 GCP
            "/home/u/.docker/config.json",            // 014 Docker
            "/home/u/.mozilla/firefox/p/logins.json", // 015 browser
            "/home/u/vault.kdbx",                     // 016 password manager
            "/home/u/.gnupg/private-keys-v1.d/x.key", // 017 GPG keyring
        ] {
            assert!(
                is_credential_path(path),
                "{path}: must be forwarded — a NN-L-FIM-011..017 rule consumes it"
            );
        }
        // BUG-012 boot-noise paths — none carries a read rule, all
        // MUST be dropped at the drain (is_credential_path == false).
        for path in &[
            "/etc/nsswitch.conf",
            "/etc/pam.d/common-auth",
            "/etc/group",
            "/usr/bin/dash",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/login.defs",
        ] {
            assert!(
                !is_credential_path(path),
                "{path}: read carries no rule — must be dropped as noise, not forwarded"
            );
        }
    }

    // ── NN-L-FIM-011 (AWS) ──────────────────────────────────────

    #[test]
    fn fim011_fires_on_aws_cred_read_by_unknown_process() {
        let r = NnLFim011AwsCredsRead;
        for path in &[
            "/root/.aws/credentials",
            "/root/.aws/config",
            "/home/alice/.aws/credentials",
            "/home/bob/.aws/config",
        ] {
            let v = r
                .evaluate(&fim_event_with_comm(FimOp::Opened, path, "evil"))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.category, "fim_credential_access");
        }
    }

    #[test]
    fn fim011_does_not_fire_on_a_delete_or_non_aws_path() {
        let r = NnLFim011AwsCredsRead;
        // A delete reads nothing and swaps nothing in; NN-AUD-286: a
        // replacement, a truncate and a chmod do fire (below).
        assert!(r
            .evaluate(&fim_event_with_comm(
                FimOp::Deleted,
                "/root/.aws/credentials",
                "evil"
            ))
            .is_none());
        // Random path with "aws" in it — must NOT match the
        // /.aws/ fragment pattern.
        assert!(r
            .evaluate(&fim_event_with_comm(
                FimOp::Opened,
                "/etc/aws-cli/something",
                "evil"
            ))
            .is_none());
    }

    /// External audit NN-AUD-286 (FIMR-012): the credentials replaced by a
    /// rename over them (`mv new ~/.aws/credentials`: `Modified`, FIMR-004)
    /// or truncated by path never open the watched inode, and drew no
    /// verdict.
    #[test]
    fn fim011_fires_on_replaced_credentials() {
        let v = NnLFim011AwsCredsRead
            .evaluate(&fim_event_with_comm(
                FimOp::Modified,
                "/root/.aws/credentials",
                "evil",
            ))
            .expect("a replacement fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::KillProcess, Severity::High)
        );
        assert!(
            v.reasoning
                .contains("changed without being opened (Modified)"),
            "{}",
            v.reasoning
        );
        for (rule, path) in [
            (
                &NnLFim012AzureCredsRead as &dyn Rule,
                "/root/.azure/msal_token_cache.json",
            ),
            (
                &NnLFim013GcpCredsRead,
                "/root/.config/gcloud/credentials.db",
            ),
            (&NnLFim014DockerCredsRead, "/root/.docker/config.json"),
        ] {
            assert!(
                rule.evaluate(&fim_event_with_comm(FimOp::Modified, path, "evil"))
                    .is_some(),
                "{}: {path}",
                rule.id()
            );
        }
    }

    /// NN-AUD-286: a chmod or chown of the credentials (`AttrChanged`) —
    /// `chmod o+r ~/.aws/credentials` hands them to every user.
    #[test]
    fn fim011_fires_on_chmod_widening() {
        let v = NnLFim011AwsCredsRead
            .evaluate(&fim_event_with_comm(
                FimOp::AttrChanged,
                "/home/alice/.aws/credentials",
                "chmod",
            ))
            .expect("a chmod fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// NN-AUD-286: the cloud's own CLI rewriting its credentials (`aws
    /// configure`) stays exempt, told by what the kernel executed.
    #[test]
    fn fim011_own_cli_modify_is_exempt() {
        let (_tmp, lineage) = exec_fixture(&[
            (
                100,
                "/usr/local/aws-cli/v2/2.17.0/dist/aws",
                &["aws", "configure"],
            ),
            (101, "/usr/bin/python3.12", &["python3", "/tmp/x.py"]),
        ]);
        let rules = rules_by_id(&lineage);
        let r = &rules["NN-L-FIM-011_AwsCredsRead"];
        for op in [FimOp::Modified, FimOp::AttrChanged] {
            assert!(r
                .evaluate(&written_by(op, "/root/.aws/credentials", 100, "aws"))
                .is_none());
            let v = r
                .evaluate(&written_by(op, "/root/.aws/credentials", 101, "aws"))
                .expect("python named aws fires");
            assert_eq!(v.action, ResponseAction::KillProcess);
        }
    }

    // ── NN-L-FIM-012 (Azure) ────────────────────────────────────

    #[test]
    fn fim012_fires_on_azure_cred_read_by_unknown_process() {
        let r = NnLFim012AzureCredsRead;
        for path in &[
            "/root/.azure/azureProfile.json",
            "/home/alice/.azure/accessTokens.json",
        ] {
            let v = r
                .evaluate(&fim_event_with_comm(FimOp::Opened, path, "evil"))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
        }
    }

    // ── NN-L-FIM-013 (GCP) ──────────────────────────────────────

    #[test]
    fn fim013_fires_on_gcp_cred_read_by_unknown_process() {
        let r = NnLFim013GcpCredsRead;
        for path in &[
            "/root/.config/gcloud/credentials.db",
            "/root/.config/gcloud/access_tokens.db",
            "/home/alice/.config/gcloud/application_default_credentials.json",
            "/home/alice/.config/gcloud/legacy_credentials/u@example.com/adc.json",
        ] {
            let v = r
                .evaluate(&fim_event_with_comm(FimOp::Opened, path, "evil"))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
        }
    }

    // ── NN-L-FIM-014 (Docker) ───────────────────────────────────

    #[test]
    fn fim014_fires_on_docker_cred_read_by_unknown_process() {
        let r = NnLFim014DockerCredsRead;
        for path in &[
            "/root/.docker/config.json",
            "/home/alice/.docker/config.json",
            "/var/lib/docker/credentials.json",
        ] {
            let v = r
                .evaluate(&fim_event_with_comm(FimOp::Opened, path, "evil"))
                .unwrap_or_else(|| panic!("expected fire on {path}"));
            assert_eq!(v.severity, Severity::High);
        }
    }

    // ── C5.3 cross-cutting invariants ───────────────────────────

    #[test]
    fn cred_read_rules_share_credential_access_category() {
        for r in [
            NnLFim011AwsCredsRead.category(),
            NnLFim012AzureCredsRead.category(),
            NnLFim013GcpCredsRead.category(),
            NnLFim014DockerCredsRead.category(),
        ] {
            assert_eq!(r, "fim_credential_access");
        }
    }

    #[test]
    fn fim_builder_has_twenty_five_rules() {
        // C5 shipped 9, C5.1 added 1, C5.3 added 4 → 14; Tappa 10.5
        // D3 adds NN-L-FIM-015..023 (9) → 23; Tappa 9.5.1 adds
        // NN-L-FIM-024 (anti-tamper bait) → 24; review 86 adds
        // NN-L-FIM-025 (file capability granted) → 25.
        let n = fim_rules(TrustedInstallerOverride::inert_arc()).len();
        assert_eq!(n, 25, "expected 25 FIM rules, got {n}");
    }

    // ── Tappa 9.5.1 — NN-L-FIM-024 anti-tamper bait ─────────────────

    /// fim_event() uses modifier_pid = 42; construct the rule with a
    /// DIFFERENT own_pid so the attacker writes (pid 42) detonate.
    const TEST_AGENT_PID: u32 = 99_999;

    #[test]
    fn fim024_fires_on_every_honeypot_path() {
        let rule = NnLFim024AntiTamperHoneypotModified::new(TEST_AGENT_PID);
        for p in HONEYPOT_PATHS {
            let v = rule
                .evaluate(&fim_event(FimOp::Modified, p))
                .unwrap_or_else(|| panic!("FIM-024 must fire on {p}"));
            assert_eq!(v.severity, Severity::Critical, "{p} severity");
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{p} action");
            assert_eq!(v.rule_id, "NN-L-FIM-024_AntiTamperHoneypotModified");
        }
    }

    #[test]
    fn fim024_fires_on_create_delete_rename_too() {
        let rule = NnLFim024AntiTamperHoneypotModified::new(TEST_AGENT_PID);
        let p = "/etc/northnarrow/kill_switch.conf";
        for op in [FimOp::Created, FimOp::Deleted, FimOp::Renamed] {
            assert!(
                rule.evaluate(&fim_event(op, p)).is_some(),
                "FIM-024 must fire on {op:?} of a bait file"
            );
        }
        // Opened/Linked are not mutations → no fire.
        for op in [FimOp::Opened, FimOp::Linked] {
            assert!(
                rule.evaluate(&fim_event(op, p)).is_none(),
                "FIM-024 must NOT fire on {op:?} (not a mutation)"
            );
        }
    }

    #[test]
    fn fim024_does_not_fire_on_own_pid_backstop() {
        // own_pid == the event's modifier_pid (42) → boot-recreate
        // self-guard suppresses the verdict.
        let rule = NnLFim024AntiTamperHoneypotModified::new(42);
        assert!(
            rule.evaluate(&fim_event(FimOp::Created, "/run/northnarrow/pause.flag"))
                .is_none(),
            "FIM-024 must NOT fire when modifier_pid == own_pid"
        );
    }

    #[test]
    fn fim024_does_not_fire_on_non_honeypot_path() {
        let rule = NnLFim024AntiTamperHoneypotModified::new(TEST_AGENT_PID);
        // Same dirs, different (real-looking) filenames must not match.
        for p in [
            "/etc/northnarrow/agent.conf",
            "/var/lib/northnarrow/canaries.jsonl",
            "/run/northnarrow/agent.pid",
            "/etc/northnarrow/kill_switch.conf.bak",
        ] {
            assert!(
                rule.evaluate(&fim_event(FimOp::Modified, p)).is_none(),
                "FIM-024 must NOT fire on non-bait path {p}"
            );
        }
    }

    #[test]
    fn fim024_reasoning_maps_t1562_001() {
        let rule = NnLFim024AntiTamperHoneypotModified::new(TEST_AGENT_PID);
        let v = rule
            .evaluate(&fim_event(FimOp::Modified, HONEYPOT_PATHS[0]))
            .expect("fires");
        assert!(
            v.reasoning.contains("T1562.001"),
            "reasoning must map MITRE T1562.001, got: {}",
            v.reasoning
        );
    }

    /// Static-leak contract: no attacker-readable verdict string (rule
    /// name, category, reasoning, or bait PATHS) may reveal the
    /// deception. The immutable rule ID is the operator-facing telemetry
    /// key and is deliberately OUTSIDE this contract.
    #[test]
    fn fim024_user_visible_strings_have_no_deception_leak() {
        let banned = ["honeypot", "decoy", "canary", "bait", "trap"];
        let rule = NnLFim024AntiTamperHoneypotModified::new(TEST_AGENT_PID);
        let v = rule
            .evaluate(&fim_event(FimOp::Modified, HONEYPOT_PATHS[0]))
            .expect("fires");
        let mut surfaces = vec![
            rule.name().to_lowercase(),
            rule.category().to_lowercase(),
            v.reasoning.to_lowercase(),
        ];
        surfaces.extend(HONEYPOT_PATHS.iter().map(|p| p.to_lowercase()));
        for s in &surfaces {
            for b in banned {
                assert!(
                    !s.contains(b),
                    "leaky term {b:?} in attacker-visible string {s:?}"
                );
            }
        }
    }

    #[test]
    fn fim024_honeypot_paths_are_ten_unique() {
        let set: std::collections::BTreeSet<_> = HONEYPOT_PATHS.iter().collect();
        assert_eq!(set.len(), 10, "expected 10 unique honeypot paths");
    }

    // ── Tappa 10.5 D3 — table-driven coverage (§13 Q8) ──────────────
    //
    // The 9 new FIM rules (NN-L-FIM-015..023) are a homogeneous
    // path-pattern family, so per §13 Q8 they're covered by a single
    // `(rule, op, path, comm, expect)` table rather than 27
    // near-identical bespoke pairs. Each row asserts either a fired
    // verdict (severity + action) or no fire. Positive, negative
    // (wrong path / wrong op) cases are all rows. Since review 85 a
    // client's own access is exempted by [`OwnClient`] on what the kernel
    // executed, so these rows fire whatever the comm.

    /// Expected outcome of a table row.
    enum Expect {
        Fire(Severity, ResponseAction),
        NoFire,
    }

    fn run_d3_case(rule: &dyn Rule, op: FimOp, path: &str, comm: &str, expect: Expect) {
        let ev = fim_event_with_comm(op, path, comm);
        let got = rule.evaluate(&ev);
        match expect {
            Expect::Fire(sev, act) => {
                let v = got.unwrap_or_else(|| {
                    panic!(
                        "{} should fire on op={op:?} path={path} comm={comm}",
                        rule.id()
                    )
                });
                assert_eq!(v.severity, sev, "{} severity", rule.id());
                assert_eq!(v.action, act, "{} action", rule.id());
                assert_eq!(v.event_filename, path, "{} event_filename", rule.id());
            }
            Expect::NoFire => assert!(
                got.is_none(),
                "{} must NOT fire on op={op:?} path={path} comm={comm}",
                rule.id()
            ),
        }
    }

    #[test]
    fn d3_fim_rules_table() {
        use Expect::{Fire, NoFire};
        use FimOp::*;
        use ResponseAction::{KillProcess, KillProcessTree, Log};

        // Each tuple: (rule, op, path, modifier_comm, expect).
        // `attacker` is the canonical non-allowlisted modifier comm.
        #[allow(clippy::type_complexity)]
        let cases: Vec<(Box<dyn Rule>, FimOp, &str, &str, Expect)> = vec![
            // FIM-015 browser creds — read/write by non-browser fires;
            // browser comm exempt; wrong path / wrong op no-fire.
            (
                Box::new(NnLFim015BrowserCredsAccessed),
                Opened,
                "/home/u/.config/google-chrome/Default/Login Data",
                "curl",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim015BrowserCredsAccessed),
                Modified,
                "/home/u/.mozilla/firefox/p.default/logins.json",
                "python3",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim015BrowserCredsAccessed),
                Opened,
                "/home/u/.mozilla/firefox/p.default/key4.db",
                "firefox",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            (
                Box::new(NnLFim015BrowserCredsAccessed),
                Opened,
                "/home/u/Documents/notes.txt",
                "curl",
                NoFire, // not a cred store
            ),
            (
                Box::new(NnLFim015BrowserCredsAccessed),
                Deleted,
                "/home/u/.config/google-chrome/Default/Login Data",
                "curl",
                NoFire, // op outside {Opened, Modified}
            ),
            // FIM-016 password manager DB.
            (
                Box::new(NnLFim016PasswordManagerDbAccessed),
                Opened,
                "/home/u/secrets.kdbx",
                "cat",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim016PasswordManagerDbAccessed),
                Opened,
                "/home/u/.password-store/aws/key.gpg",
                "exfil",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim016PasswordManagerDbAccessed),
                Opened,
                "/home/u/secrets.kdbx",
                "keepassxc",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            // FIM-017 GPG keyring.
            (
                Box::new(NnLFim017GpgKeyringAccessed),
                Opened,
                "/home/u/.gnupg/private-keys-v1.d/abc.key",
                "scp",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim017GpgKeyringAccessed),
                Opened,
                "/home/u/.gnupg/pubring.kbx",
                "gpg",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            // FIM-018 lastlog tamper — Modified by non-login fires;
            // login-session comm exempt.
            (
                Box::new(NnLFim018LastlogTampered),
                Modified,
                "/var/log/lastlog",
                "dd",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim018LastlogTampered),
                Modified,
                "/var/log/lastlog",
                "login",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            (
                Box::new(NnLFim018LastlogTampered),
                Created,
                "/var/log/lastlog",
                "dd",
                NoFire, // only Modified
            ),
            // FIM-019 wtmp/btmp tamper.
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/wtmp",
                "sed",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/btmp",
                "sshd",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/btmp",
                "sshd-session",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            // Review item 38: systemd's pre-exec child of a getty unit
            // writes the UtmpIdentifier= record as `(agetty)`.
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/wtmp",
                "(agetty)",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            (
                Box::new(NnLFim018LastlogTampered),
                Modified,
                "/var/log/lastlog",
                "(login)",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            // systemd-update-utmp's boot runlevel record, under its
            // truncated 15-character comm.
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/wtmp",
                "systemd-update-",
                Fire(Severity::High, KillProcess), // review 85: exempted by OwnClient, not by comm
            ),
            // The parenthesized form only unwraps to a legit name: a
            // foreign tool stays detected, and one layer is stripped.
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/wtmp",
                "(sed)",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/wtmp",
                "((agetty))",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim019WtmpBtmpTampered),
                Modified,
                "/var/log/wtmp",
                "(agetty",
                Fire(Severity::High, KillProcess),
            ),
            // FIM-020 shell history cleared — Delete/Rename fires;
            // Modified (normal append) does not.
            (
                Box::new(NnLFim020ShellHistoryCleared),
                Deleted,
                "/home/u/.bash_history",
                "bash",
                Fire(Severity::Medium, Log),
            ),
            (
                Box::new(NnLFim020ShellHistoryCleared),
                Renamed,
                "/home/u/.zsh_history",
                "mv",
                Fire(Severity::Medium, Log),
            ),
            (
                Box::new(NnLFim020ShellHistoryCleared),
                Modified,
                "/home/u/.bash_history",
                "bash",
                NoFire, // normal append, not a clear
            ),
            // FIM-021 PAM module — Created/Modified .so under security/
            // is Critical.
            (
                Box::new(NnLFim021PamModuleModified),
                Modified,
                "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
                "attacker",
                Fire(Severity::Critical, KillProcessTree),
            ),
            (
                Box::new(NnLFim021PamModuleModified),
                Created,
                "/lib/security/pam_evil.so",
                "attacker",
                Fire(Severity::Critical, KillProcessTree),
            ),
            (
                Box::new(NnLFim021PamModuleModified),
                Modified,
                "/etc/security/limits.conf",
                "attacker",
                NoFire, // under security/ but not a .so
            ),
            // FIM-022 ld.so.preload — exact path, Created/Modified,
            // Critical, no comm exemption.
            (
                Box::new(NnLFim022LdSoPreloadModified),
                Created,
                "/etc/ld.so.preload",
                "attacker",
                Fire(Severity::Critical, KillProcessTree),
            ),
            (
                Box::new(NnLFim022LdSoPreloadModified),
                Modified,
                "/etc/ld.so.preload",
                "root-but-still-fires",
                Fire(Severity::Critical, KillProcessTree),
            ),
            (
                Box::new(NnLFim022LdSoPreloadModified),
                Modified,
                "/etc/ld.so.conf",
                "attacker",
                NoFire, // similar name, different file
            ),
            // FIM-023 systemd timer.
            (
                Box::new(NnLFim023SystemdTimerCreated),
                Created,
                "/etc/systemd/system/backdoor.timer",
                "attacker",
                Fire(Severity::High, KillProcess),
            ),
            (
                Box::new(NnLFim023SystemdTimerCreated),
                Created,
                "/etc/systemd/system/backdoor.service",
                "attacker",
                NoFire, // .service is NN-L-FIM-009's job, not -023
            ),
        ];

        for (rule, op, path, comm, expect) in cases {
            run_d3_case(rule.as_ref(), op, path, comm, expect);
        }
    }

    // ── review 49 — package-manager writes are recorded, not killed ──

    /// A FIM event written by `pid`, against a lineage tracker whose
    /// `/proc` is a temp dir: the spawn cache answers the lineage, and
    /// `/proc` shows only the package managers, running (NN-AUD-284: the
    /// carve-out covers a write while the transaction runs).
    fn pkg_fixture() -> (tempfile::TempDir, AuthSessionTracker) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // apt-get (100) → dpkg (200) → postinst sh (300) → systemctl (400)
        t.ingest_spawn(100, 1, "/usr/bin/apt-get", 1);
        t.ingest_spawn(200, 100, "/usr/bin/dpkg", 2);
        t.ingest_spawn(300, 200, "/bin/sh", 3);
        t.ingest_spawn(400, 300, "/usr/bin/systemctl", 4);
        // an unrelated root shell (500) → cp (600)
        t.ingest_spawn(500, 1, "/usr/bin/bash", 5);
        t.ingest_spawn(600, 500, "/usr/bin/cp", 6);
        running_proc(tmp.path(), 100, 1);
        running_proc(tmp.path(), 200, 100);
        (tmp, t)
    }

    /// `/proc/<pid>` of a running process (state `S`).
    fn running_proc(dir: &std::path::Path, pid: u32, ppid: u32) {
        let pid_dir = dir.join(pid.to_string());
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(
            pid_dir.join("stat"),
            format!("{pid} (p) S {ppid} {pid} {pid} 0 -1 0\n"),
        )
        .unwrap();
    }

    fn written_by(op: FimOp, path: &str, pid: u32, comm: &str) -> Event {
        let Event::Fim(mut fe) = fim_event_with_comm(op, path, comm) else {
            unreachable!()
        };
        fe.modifier_pid = pid;
        Event::Fim(fe)
    }

    fn rules_by_id(lineage: &AuthSessionTracker) -> HashMap<&'static str, Box<dyn Rule>> {
        fim_rules_with_lineage(TrustedInstallerOverride::inert_arc(), lineage.clone())
            .into_iter()
            .map(|r| (r.id(), r))
            .collect()
    }

    /// The shapes the lab saw dpkg killed for (FIM-007/009/021), plus the
    /// other wrapped rules, each written by dpkg or one of its children.
    #[test]
    fn package_manager_writes_are_logged_not_killed() {
        let (_tmp, lineage) = pkg_fixture();
        let rules = rules_by_id(&lineage);
        let cases: &[(&str, FimOp, &str, u32, &str)] = &[
            (
                "NN-L-FIM-009_SystemdUnitDropped",
                FimOp::Created,
                "/usr/lib/systemd/system/rsync.service.dpkg-new",
                200,
                "dpkg",
            ),
            (
                "NN-L-FIM-009_SystemdUnitDropped",
                FimOp::Created,
                "/etc/systemd/system/multi-user.target.wants/x.service",
                400,
                "systemctl",
            ),
            (
                "NN-L-FIM-007_CronDropInCreated",
                FimOp::Created,
                "/etc/cron.d/e2scrub_all",
                200,
                "dpkg",
            ),
            (
                "NN-L-FIM-021_PamModuleModified",
                FimOp::Created,
                "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
                200,
                "dpkg",
            ),
            (
                "NN-L-FIM-008_KernelModuleModified",
                FimOp::Created,
                "/lib/modules/6.8.0-146-generic/kernel/fs/x.ko",
                200,
                "dpkg",
            ),
            (
                "NN-L-FIM-003_SensitiveConfigModified",
                FimOp::Modified,
                "/etc/passwd",
                300,
                "useradd",
            ),
            (
                "NN-L-FIM-001_SystemBinaryModified",
                FimOp::Modified,
                "/usr/bin/rsync",
                200,
                "dpkg",
            ),
        ];
        for (id, op, path, pid, comm) in cases {
            let rule = rules.get(id).unwrap_or_else(|| panic!("{id} missing"));
            let killer = rule
                .evaluate(&written_by(*op, path, 600, "cp"))
                .unwrap_or_else(|| panic!("{id} must fire on {path}"));
            assert_ne!(
                killer.action,
                ResponseAction::Log,
                "{id}: foreign writer keeps its response"
            );
            let v = rule
                .evaluate(&written_by(*op, path, *pid, comm))
                .unwrap_or_else(|| panic!("{id} must still record {path}"));
            assert_eq!(v.rule_id, *id);
            assert_eq!(v.action, ResponseAction::Log, "{id} on {path}");
            assert_eq!(v.severity, Severity::Low, "{id} on {path}");
            assert!(v.reasoning.contains("package manager"), "{}", v.reasoning);
        }
    }

    /// The carve-out reads the kernel-resolved lineage, never comm: a
    /// process merely NAMED dpkg is still killed.
    #[test]
    fn comm_named_dpkg_is_not_trusted() {
        let (_tmp, lineage) = pkg_fixture();
        let rules = rules_by_id(&lineage);
        let v = rules["NN-L-FIM-009_SystemdUnitDropped"]
            .evaluate(&written_by(
                FimOp::Created,
                "/etc/systemd/system/evil.service",
                600,
                "dpkg",
            ))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// `/etc/ld.so.preload` stays a kill even for dpkg: no mainstream
    /// package ships it, and it is the LD_PRELOAD-rootkit signature.
    #[test]
    fn ld_so_preload_is_not_carved_out() {
        let (_tmp, lineage) = pkg_fixture();
        let rules = rules_by_id(&lineage);
        let v = rules["NN-L-FIM-022_LdSoPreloadModified"]
            .evaluate(&written_by(
                FimOp::Created,
                "/etc/ld.so.preload",
                200,
                "dpkg",
            ))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// A rule's own Log verdict passes through untouched, and the wrapper
    /// keeps id / name / category of the rule it wraps.
    #[test]
    fn package_managed_wrapper_is_transparent_otherwise() {
        struct AlwaysLog;
        impl Rule for AlwaysLog {
            fn id(&self) -> &'static str {
                "TEST-LOG"
            }
            fn name(&self) -> &'static str {
                "always log"
            }
            fn category(&self) -> &'static str {
                "test"
            }
            fn evaluate(&self, event: &Event) -> Option<Verdict> {
                let fe = as_fim(event)?;
                Some(fim_verdict(
                    self,
                    fe,
                    ResponseAction::Log,
                    Severity::High,
                    "own reasoning",
                ))
            }
        }
        let (_tmp, lineage) = pkg_fixture();
        let w = PackageManaged::new(Box::new(AlwaysLog), lineage);
        assert_eq!(
            (w.id(), w.name(), w.category()),
            ("TEST-LOG", "always log", "test")
        );
        let v = w
            .evaluate(&written_by(FimOp::Modified, "/etc/passwd", 200, "dpkg"))
            .unwrap();
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.reasoning, "own reasoning");
    }

    /// Tappa 10.9 step 1 (design Q8): a credential-store open found by the
    /// file-open sensor's name table (any home) is reported at the same
    /// severity but never acted on; the same open of a watched file still
    /// kills.
    #[test]
    fn wide_coverage_cred_read_is_reported_not_killed() {
        let watched = fim_event_with_comm(FimOp::Opened, "/root/.aws/credentials", "cat");
        let v = NnLFim011AwsCredsRead
            .evaluate(&watched)
            .expect("watched read fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
        let mut wide =
            fim_event_with_comm(FimOp::Opened, "/home/alice/.aws/credentials", "python3");
        if let Event::Fim(fe) = &mut wide {
            fe.wide_coverage = true;
        }
        let v = NnLFim011AwsCredsRead
            .evaluate(&wide)
            .expect("wide-coverage read fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.event_filename, "/home/alice/.aws/credentials");
    }

    /// Q8, decided 2026-10-12: a wide-coverage credential read by another,
    /// non-root user is acted on; the owner's own read and root's (backups)
    /// are only reported, and so is a read whose owner is unknown.
    #[test]
    fn foreign_non_root_cred_read_is_acted_on() {
        let read = |reader: u32, owner: Option<u32>| {
            let mut e = fim_event_with_comm(FimOp::Opened, "/home/alice/.aws/credentials", "cat");
            if let Event::Fim(fe) = &mut e {
                fe.wide_coverage = true;
                fe.modifier_uid = reader;
                fe.owner_uid = owner;
            }
            NnLFim011AwsCredsRead.evaluate(&e).expect("fires")
        };
        let v = read(1001, Some(1000));
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(v
            .reasoning
            .contains("uid 1001 read a file owned by uid 1000"));
        assert_eq!(read(1000, Some(1000)).action, ResponseAction::Log);
        assert_eq!(read(0, Some(1000)).action, ResponseAction::Log);
        assert_eq!(read(1001, None).action, ResponseAction::Log);
    }

    /// Q8: a non-root reader that holds a DAC capability on the host reads
    /// as root does (restic run as its own user with CAP_DAC_READ_SEARCH):
    /// reported, not acted on.
    #[test]
    fn dac_capable_reader_is_treated_as_root() {
        let mut e = fim_event_with_comm(FimOp::Opened, "/home/alice/.aws/credentials", "restic");
        if let Event::Fim(fe) = &mut e {
            fe.wide_coverage = true;
            fe.modifier_uid = 998;
            fe.owner_uid = Some(1000);
            fe.reader_dac_capable = true;
        }
        let v = NnLFim011AwsCredsRead.evaluate(&e).expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(!v.reasoning.contains("read a file owned by"));
    }

    // ── review 52 — interactive admin writes are recorded, not killed ──

    /// `/proc` entries for an interactive admin session: login uid 1000
    /// and, unless `tty_nr` is 0, a terminal.
    fn session_proc(dir: &std::path::Path, pid: u32, ppid: u32, tty_nr: i64) {
        let pid_dir = dir.join(pid.to_string());
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(pid_dir.join("loginuid"), "1000").unwrap();
        std::fs::write(
            pid_dir.join("stat"),
            format!("{pid} (w) S {ppid} {pid} {pid} {tty_nr} -1 0\n"),
        )
        .unwrap();
    }

    /// bash (700) → sudo (710) → vim (720, terminal) | apt-get (730) →
    /// dpkg (740) | tee (750, no terminal); bash (500) → cp (600): a root
    /// shell with a terminal and a login uid but no elevation binary.
    fn admin_fixture() -> (tempfile::TempDir, AuthSessionTracker) {
        let (tmp, t) = pkg_fixture();
        t.ingest_spawn(700, 1, "/usr/bin/bash", 7);
        t.ingest_spawn(710, 700, "/usr/bin/sudo", 8);
        t.ingest_spawn(720, 710, "/usr/bin/vim.basic", 9);
        t.ingest_spawn(730, 710, "/usr/bin/apt-get", 10);
        t.ingest_spawn(740, 730, "/usr/bin/dpkg", 11);
        t.ingest_spawn(750, 710, "/usr/bin/tee", 12);
        session_proc(tmp.path(), 720, 710, 34816);
        session_proc(tmp.path(), 740, 730, 34816);
        session_proc(tmp.path(), 750, 710, 0);
        session_proc(tmp.path(), 600, 500, 34816);
        (tmp, t)
    }

    #[test]
    fn interactive_admin_config_writes_are_logged_at_rule_severity() {
        let (_tmp, lineage) = admin_fixture();
        let rules = rules_by_id(&lineage);
        let cases: &[(&str, FimOp, &str)] = &[
            (
                "NN-L-FIM-003_SensitiveConfigModified",
                FimOp::Modified,
                "/etc/passwd",
            ),
            (
                "NN-L-FIM-007_CronDropInCreated",
                FimOp::Created,
                "/etc/cron.d/backup",
            ),
            (
                "NN-L-FIM-009_SystemdUnitDropped",
                FimOp::Created,
                "/etc/systemd/system/backup.service",
            ),
            (
                "NN-L-FIM-023_SystemdTimerCreated",
                FimOp::Created,
                "/etc/systemd/system/backup.timer",
            ),
        ];
        for (id, op, path) in cases {
            let rule = rules.get(id).unwrap_or_else(|| panic!("{id} missing"));
            let killed = rule
                .evaluate(&written_by(*op, path, 600, "cp"))
                .unwrap_or_else(|| panic!("{id} must fire on {path}"));
            assert_ne!(
                killed.action,
                ResponseAction::Log,
                "{id}: root shell, no sudo"
            );
            let no_tty = rule.evaluate(&written_by(*op, path, 750, "tee")).unwrap();
            assert_ne!(no_tty.action, ResponseAction::Log, "{id}: no terminal");
            let v = rule.evaluate(&written_by(*op, path, 720, "vim")).unwrap();
            assert_eq!(v.action, ResponseAction::Log, "{id} on {path}");
            assert_eq!(v.severity, killed.severity, "{id} keeps its severity");
            assert!(
                v.reasoning
                    .contains("interactive sudo/su session (login uid 1000, terminal)"),
                "{}",
                v.reasoning
            );
        }
    }

    /// The package carve-out still applies inside an admin session (`sudo
    /// apt install`: Log + Low), and the rootkit-shaped rules are not
    /// wrapped: an admin session writing them is still acted on.
    #[test]
    fn interactive_admin_leaves_package_and_rootkit_rules_alone() {
        let (_tmp, lineage) = admin_fixture();
        let rules = rules_by_id(&lineage);
        let dpkg = rules["NN-L-FIM-009_SystemdUnitDropped"]
            .evaluate(&written_by(
                FimOp::Created,
                "/usr/lib/systemd/system/x.service",
                740,
                "dpkg",
            ))
            .unwrap();
        assert_eq!(dpkg.action, ResponseAction::Log);
        assert_eq!(dpkg.severity, Severity::Low);
        for (id, path) in [
            ("NN-L-FIM-001_SystemBinaryModified", "/usr/bin/rsync"),
            ("NN-L-FIM-022_LdSoPreloadModified", "/etc/ld.so.preload"),
        ] {
            let v = rules[id]
                .evaluate(&written_by(FimOp::Modified, path, 720, "cp"))
                .unwrap_or_else(|| panic!("{id} must fire on {path}"));
            assert_ne!(v.action, ResponseAction::Log, "{id} is not wrapped");
        }
    }

    // ── review 85 — clients told by what the kernel executed ──────────

    /// A lineage tracker whose `/proc` is an empty temp dir, with `exec`
    /// ingested for `pid` as the exec sensor would (exe, argv).
    fn exec_fixture(execs: &[(u32, &str, &[&str])]) -> (tempfile::TempDir, AuthSessionTracker) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        for (pid, exe, argv) in execs {
            let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            t.ingest_spawn_with_argv(*pid, 1, exe, &argv, 1);
        }
        (tmp, t)
    }

    fn read_by(path: &str, pid: u32, comm: &str) -> Event {
        written_by(FimOp::Opened, path, pid, comm)
    }

    /// Each store's own client — a binary, a script run by an
    /// interpreter, or a client's bundled runtime — reads its store
    /// without a verdict.
    #[test]
    fn own_clients_are_told_by_their_exec() {
        let (_tmp, lineage) = exec_fixture(&[
            (
                100,
                "/usr/local/aws-cli/v2/2.17.0/dist/aws",
                &["aws", "s3", "ls"],
            ),
            (
                101,
                "/usr/bin/python3.12",
                &["/usr/bin/python3", "/usr/bin/aws", "s3"],
            ),
            (
                102,
                "/usr/bin/python3.12",
                &[
                    "python3",
                    "-S",
                    "/usr/lib/google-cloud-sdk/lib/gcloud.py",
                    "auth",
                ],
            ),
            (
                103,
                "/opt/az/bin/python3",
                &["/opt/az/bin/python3", "-Im", "azure.cli"],
            ),
            (104, "/usr/bin/dockerd", &["dockerd"]),
            (
                105,
                "/snap/firefox/4793/usr/lib/firefox/firefox",
                &["firefox"],
            ),
            (106, "/usr/bin/gpg", &["gpg", "--decrypt"]),
            (107, "/usr/bin/bash", &["bash", "/usr/bin/pass", "show"]),
            (108, "/usr/lib/openssh/sshd-session", &["sshd-session"]),
            (
                109,
                "/usr/lib/systemd/systemd-executor",
                &["systemd-executor"],
            ),
        ]);
        let rules = rules_by_id(&lineage);
        let cases: &[(&str, Event)] = &[
            (
                "NN-L-FIM-011_AwsCredsRead",
                read_by("/root/.aws/credentials", 100, "aws"),
            ),
            (
                "NN-L-FIM-011_AwsCredsRead",
                read_by("/root/.aws/credentials", 101, "aws"),
            ),
            (
                "NN-L-FIM-013_GcpCredsRead",
                read_by("/root/.config/gcloud/credentials.db", 102, "python3"),
            ),
            (
                "NN-L-FIM-012_AzureCredsRead",
                read_by("/root/.azure/msal_token_cache.json", 103, "python3"),
            ),
            (
                "NN-L-FIM-014_DockerCredsRead",
                read_by("/root/.docker/config.json", 104, "dockerd"),
            ),
            (
                "NN-L-FIM-015_BrowserCredsAccessed",
                read_by(
                    "/home/u/snap/firefox/common/.mozilla/firefox/p/key4.db",
                    105,
                    "firefox",
                ),
            ),
            (
                "NN-L-FIM-017_GpgKeyringAccessed",
                read_by("/home/u/.gnupg/pubring.kbx", 106, "gpg"),
            ),
            (
                "NN-L-FIM-016_PasswordManagerDbAccessed",
                read_by("/home/u/.password-store/x.gpg", 107, "pass"),
            ),
            (
                "NN-L-FIM-019_WtmpBtmpTampered",
                written_by(FimOp::Modified, "/var/log/btmp", 108, "sshd-session"),
            ),
            (
                "NN-L-FIM-019_WtmpBtmpTampered",
                written_by(FimOp::Modified, "/var/log/wtmp", 109, "(agetty)"),
            ),
        ];
        for (id, ev) in cases {
            let rule = rules.get(id).unwrap_or_else(|| panic!("{id} missing"));
            assert!(
                rule.evaluate(ev).is_none(),
                "{id}: own client must pass: {ev:?}"
            );
        }
    }

    /// The lab's spoofs: a process that only names itself a client is
    /// acted on, and the reasoning says what the kernel ran.
    #[test]
    fn a_comm_alone_never_makes_a_client() {
        let (_tmp, lineage) = exec_fixture(&[
            // python renamed with prctl(PR_SET_NAME): an inline program.
            (
                200,
                "/usr/bin/python3.12",
                &["python3", "-c", "open('/root/.aws/credentials')"],
            ),
            // a copy named like the client, outside a system tree.
            (201, "/tmp/aws", &["/tmp/aws", "/root/.aws/credentials"]),
            // a script named like the client, outside a system tree.
            (
                202,
                "/usr/bin/python3.12",
                &["python3", "/home/u/.cache/aws", "x"],
            ),
            // a module named like the client's, from the caller's path.
            (203, "/usr/bin/python3.12", &["python3", "-m", "azure.cli"]),
            // python renamed to sshd, appending to wtmp.
            (
                204,
                "/usr/bin/python3.12",
                &["python3", "-c", "open('/var/log/wtmp','ab')"],
            ),
        ]);
        let rules = rules_by_id(&lineage);
        let cases: &[(&str, Event)] = &[
            (
                "NN-L-FIM-011_AwsCredsRead",
                read_by("/root/.aws/credentials", 200, "aws"),
            ),
            (
                "NN-L-FIM-011_AwsCredsRead",
                read_by("/root/.aws/credentials", 201, "aws"),
            ),
            (
                "NN-L-FIM-011_AwsCredsRead",
                read_by("/root/.aws/credentials", 202, "aws"),
            ),
            (
                "NN-L-FIM-012_AzureCredsRead",
                read_by("/root/.azure/msal_token_cache.json", 203, "az"),
            ),
            (
                "NN-L-FIM-019_WtmpBtmpTampered",
                written_by(FimOp::Modified, "/var/log/wtmp", 204, "sshd"),
            ),
            // never seen: no exec identity, not exempted.
            (
                "NN-L-FIM-011_AwsCredsRead",
                read_by("/root/.aws/credentials", 299, "aws"),
            ),
        ];
        for (id, ev) in cases {
            let rule = rules.get(id).unwrap_or_else(|| panic!("{id} missing"));
            let v = rule
                .evaluate(ev)
                .unwrap_or_else(|| panic!("{id}: a named impostor must be acted on: {ev:?}"));
            assert_ne!(v.action, ResponseAction::Log, "{id}");
            assert!(v.reasoning.contains("[named '"), "{}", v.reasoning);
        }
    }

    /// Q8: the real `aws` CLI run by another user against someone else's
    /// credentials file is not the owner's client at work.
    #[test]
    fn own_client_reading_another_users_store_is_still_foreign() {
        let (_tmp, lineage) = exec_fixture(&[(
            100,
            "/usr/local/aws-cli/v2/2.17.0/dist/aws",
            &["aws", "s3", "ls"],
        )]);
        let rules = rules_by_id(&lineage);
        let mut ev = read_by("/home/alice/.aws/credentials", 100, "aws");
        if let Event::Fim(fe) = &mut ev {
            fe.wide_coverage = true;
            fe.modifier_uid = 1001;
            fe.owner_uid = Some(1000);
        }
        let v = rules["NN-L-FIM-011_AwsCredsRead"]
            .evaluate(&ev)
            .expect("a foreign read is acted on");
        assert_eq!(v.action, ResponseAction::KillProcess);
        // The owner's own CLI: no verdict.
        if let Event::Fim(fe) = &mut ev {
            fe.modifier_uid = 1000;
        }
        assert!(rules["NN-L-FIM-011_AwsCredsRead"].evaluate(&ev).is_none());
    }

    #[test]
    fn system_trees_exclude_what_a_user_can_write() {
        for p in [
            "/usr/bin/aws",
            "/opt/google/chrome/chrome",
            "/snap/firefox/1/usr/lib/firefox/firefox",
        ] {
            assert!(crate::posture::lineage::in_system_tree(p), "{p}");
        }
        for p in [
            "/tmp/aws",
            "/home/u/bin/aws",
            "/root/aws",
            "/dev/shm/aws",
            "/memfd:aws (deleted)",
            "/usr/bin/aws (deleted)",
            "/usr/../tmp/aws",
        ] {
            assert!(!crate::posture::lineage::in_system_tree(p), "{p}");
        }
    }

    // ── review 83 — account tools are recorded, not killed ────────────

    #[test]
    fn account_tools_are_recorded_not_killed() {
        let (_tmp, lineage) = exec_fixture(&[
            (300, "/usr/sbin/useradd", &["useradd", "-m", "nn3"]),
            (301, "/usr/bin/passwd", &["passwd"]),
            (302, "/usr/bin/systemd-sysusers", &["systemd-sysusers"]),
            (303, "/tmp/useradd", &["/tmp/useradd"]),
            (304, "/usr/bin/python3.12", &["python3", "-c", "x"]),
        ]);
        let rules = rules_by_id(&lineage);
        let fim003 = &rules["NN-L-FIM-003_SensitiveConfigModified"];
        let fim018 = &rules["NN-L-FIM-018_LastlogTampered"];
        let by = |path: &str, pid: u32, uid: u32, comm: &str| {
            let mut e = written_by(FimOp::Modified, path, pid, comm);
            if let Event::Fim(fe) = &mut e {
                fe.modifier_uid = uid;
            }
            e
        };
        // root's useradd: recorded at the rule's severity.
        for (rule, path) in [(fim003, "/etc/passwd"), (fim018, "/var/log/lastlog")] {
            let v = rule
                .evaluate(&by(path, 300, 0, "useradd"))
                .expect("records");
            assert_eq!(v.action, ResponseAction::Log, "{path}");
            assert_eq!(v.severity, Severity::High, "{path}");
            assert!(
                v.reasoning.contains("account tool /usr/sbin/useradd"),
                "{}",
                v.reasoning
            );
        }
        // a user's own passwd: recorded at Low.
        let v = fim003
            .evaluate(&by("/etc/shadow", 301, 1000, "passwd"))
            .unwrap();
        assert_eq!((v.action, v.severity), (ResponseAction::Log, Severity::Low));
        let v = fim003
            .evaluate(&by("/etc/passwd", 302, 0, "systemd-sysusers"))
            .unwrap();
        assert_eq!(v.action, ResponseAction::Log);
        // named like a tool, but not one: still acted on.
        for (pid, comm) in [(303, "useradd"), (304, "passwd"), (399, "useradd")] {
            let v = fim003.evaluate(&by("/etc/passwd", pid, 0, comm)).unwrap();
            assert_ne!(v.action, ResponseAction::Log, "pid {pid}");
            let v = fim018
                .evaluate(&by("/var/log/lastlog", pid, 0, comm))
                .unwrap();
            assert_ne!(v.action, ResponseAction::Log, "pid {pid}");
        }
    }

    // ── review 86 — file capability granted ───────────────────────────

    fn cap_set(path: &str, pid: u32, permitted: u64, namespaced: bool) -> Event {
        let mut e = written_by(FimOp::CapabilitySet, path, pid, "python3");
        if let Event::Fim(fe) = &mut e {
            fe.capability = Some(common::wire::FileCapability {
                permitted,
                effective: true,
                namespaced,
            });
        }
        e
    }

    #[test]
    fn fim025_strips_a_granted_capability() {
        let r = NnLFim025FileCapabilityGranted::new(TrustedInstallerOverride::inert_arc());
        let v = r
            .evaluate(&cap_set("/opt/lab48/catcap", 42, 1 << 2, false))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::StripFileCapability);
        assert_eq!(
            v.severity,
            Severity::Critical,
            "dac_read_search is root-equivalent"
        );
        assert_eq!(v.event_filename, "/opt/lab48/catcap");
        assert!(
            v.reasoning.contains("cap_dac_read_search, effective"),
            "{}",
            v.reasoning
        );
        let v = r
            .evaluate(&cap_set("/usr/local/bin/node", 42, 1 << 10, false))
            .unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::StripFileCapability, Severity::High)
        );
        assert!(v.reasoning.contains("cap_net_bind_service"));
        // namespaced: only recorded.
        let v = r
            .evaluate(&cap_set("/home/u/ping", 42, 1 << 13, true))
            .unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Medium)
        );
        // an empty set grants nothing; other ops are not this rule's.
        assert!(r.evaluate(&cap_set("/opt/x", 42, 0, false)).is_none());
        assert!(r.evaluate(&fim_event(FimOp::Modified, "/opt/x")).is_none());
        assert_eq!(
            capability_names((1 << 7) | (1 << 40) | (1 << 50)),
            "cap_setuid,cap_checkpoint_restore,cap_50"
        );
    }

    /// While the operator's trusted-installer window is open, a grant is
    /// recorded and kept.
    #[test]
    fn fim025_keeps_a_grant_inside_the_trusted_installer_window() {
        let v = NnLFim025FileCapabilityGranted::new(armed_override())
            .evaluate(&cap_set("/opt/app/bin", 42, 1 << 10, false))
            .unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(
            v.reasoning.contains("trusted-installer window"),
            "{}",
            v.reasoning
        );
    }

    /// The package manager installs files with capabilities, and an
    /// administrator may grant one from a terminal: both recorded, the
    /// capability kept.
    #[test]
    fn fim025_package_manager_and_interactive_admin_keep_the_capability() {
        let (_tmp, lineage) = admin_fixture();
        let rules = rules_by_id(&lineage);
        let r = &rules["NN-L-FIM-025_FileCapabilityGranted"];
        let v = r
            .evaluate(&cap_set("/usr/bin/newuidmap", 200, 1 << 7, false))
            .unwrap();
        assert_eq!((v.action, v.severity), (ResponseAction::Log, Severity::Low));
        let v = r
            .evaluate(&cap_set("/usr/local/bin/node", 720, 1 << 10, false))
            .unwrap();
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning.contains("interactive sudo/su session"),
            "{}",
            v.reasoning
        );
        // a root shell with no sudo: stripped.
        let v = r.evaluate(&cap_set("/opt/x", 600, 1 << 7, false)).unwrap();
        assert_eq!(v.action, ResponseAction::StripFileCapability);
    }

    // ── external audit NN-AUD-284 — the package transaction proper ──

    /// External audit NN-AUD-284 (FIMR-010): `mandb` is no package
    /// manager. A user's process runs it (not set-id, so `LD_PRELOAD`
    /// applies) and has it fork `crontab`: on `main` the user's crontab
    /// install was Log + Low. The posture keeps its wider list.
    #[test]
    fn mandb_lineage_does_not_exempt_fim_rules() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // the user's shell (900) → mandb (910) → crontab (920)
        lineage.ingest_spawn(900, 1, "/usr/bin/bash", 1);
        lineage.ingest_spawn(910, 900, "/usr/bin/mandb", 2);
        lineage.ingest_spawn(920, 910, "/usr/bin/crontab", 3);
        running_proc(tmp.path(), 910, 900);
        running_proc(tmp.path(), 920, 910);
        let rules = rules_by_id(&lineage);
        let mut e = written_by(
            FimOp::Created,
            "/var/spool/cron/crontabs/nn",
            920,
            "crontab",
        );
        if let Event::Fim(fe) = &mut e {
            fe.modifier_uid = 1000;
        }
        let v = rules["NN-L-FIM-007_CronDropInCreated"]
            .evaluate(&e)
            .expect("the crontab install fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::KillProcess, Severity::High)
        );
        assert!(!v.reasoning.contains("package manager"), "{}", v.reasoning);
        assert!(lineage.is_system_daemon_mediated(920));
        assert!(!crate::posture::lineage::PACKAGE_MANAGER_EXES.contains(&"/usr/bin/mandb"));
    }

    /// NN-AUD-284: a process a finished transaction left behind is not
    /// exempt for good. dpkg (200) found running covers its child's writes;
    /// once it is gone they are covered for 30 s after it was last seen,
    /// then the rule's verdict stands.
    #[test]
    fn descendant_outliving_the_transaction_is_not_exempt() {
        let (tmp, lineage) = pkg_fixture();
        let rules = rules_by_id(&lineage);
        let r = &rules["NN-L-FIM-001_SystemBinaryModified"];
        let at = |pid: u32, ts_ns: u64| {
            let mut e = written_by(FimOp::Modified, "/usr/bin/rsync", pid, "sh");
            if let Event::Fim(fe) = &mut e {
                fe.timestamp_ns = ts_ns;
            }
            e
        };
        let t0 = 1_700_000_000_000_000_000u64;
        let s = 1_000_000_000u64;
        assert_eq!(
            r.evaluate(&at(300, t0)).unwrap().action,
            ResponseAction::Log
        );
        // dpkg exits; its child runs on
        std::fs::remove_dir_all(tmp.path().join("200")).unwrap();
        assert_eq!(
            r.evaluate(&at(300, t0 + 20 * s)).unwrap().action,
            ResponseAction::Log,
            "within the grace after dpkg was last seen running"
        );
        let v = r.evaluate(&at(300, t0 + 120 * s)).unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical),
            "two minutes after the transaction"
        );
        // apt-get (100) still runs, but the nearest package manager is the
        // finished dpkg: no cover from it.
        assert!(!lineage.is_package_transaction_write(300, t0 + 120 * s));
        assert!(lineage.is_package_transaction_write(100, t0 + 120 * s));
    }

    /// NN-AUD-284: a short `dpkg -i` that exited before any walk found it
    /// running covers what it and its children wrote within 60 s of its
    /// exec, not later.
    #[test]
    fn short_dpkg_write_within_grace_is_exempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        let exec_ns = 1_700_000_000_000_000_000u64;
        lineage.ingest_spawn(200, 1, "/usr/bin/dpkg", exec_ns);
        lineage.ingest_spawn(300, 200, "/bin/sh", exec_ns + 1_000);
        let rules = rules_by_id(&lineage);
        let r = &rules["NN-L-FIM-009_SystemdUnitDropped"];
        let at = |pid: u32, ts_ns: u64| {
            let mut e = written_by(
                FimOp::Created,
                "/usr/lib/systemd/system/x.service",
                pid,
                "dpkg",
            );
            if let Event::Fim(fe) = &mut e {
                fe.timestamp_ns = ts_ns;
            }
            e
        };
        let v = r.evaluate(&at(200, exec_ns + 2_000_000_000)).unwrap();
        assert_eq!((v.action, v.severity), (ResponseAction::Log, Severity::Low));
        let v = r.evaluate(&at(300, exec_ns + 59_000_000_000)).unwrap();
        assert_eq!(v.action, ResponseAction::Log);
        let v = r.evaluate(&at(300, exec_ns + 61_000_000_000)).unwrap();
        assert_eq!(v.action, ResponseAction::KillProcess);
    }
}
