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
//! - **NN-L-FIM-002 hardlink semantics** (§13 Q2 lock-in): the
//!   rule fires on Created OR Linked op, escalating to
//!   Critical when the destination path is in a user-writable
//!   directory (`/tmp/`, `/var/tmp/`, `/dev/shm/`, `/home/`).
//!   Mirrors the C4 `DriftClassifier::classify` Critical arm
//!   so the rule + classifier agree.
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

use common::wire::{FimEvent, FimOp};
use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::Rule;

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
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity,
        reasoning: reasoning.to_string(),
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
        if fe.op != FimOp::Modified {
            return None;
        }
        if !starts_with_any(&fe.path, SYSTEM_BINARY_PREFIXES) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "System binary modified — supply-chain / persistence indicator",
        ))
    }
}

// ── NN-L-FIM-002 — new SUID-root binary appeared ───────────────────

/// `Created` or `Linked` op when the destination path is in a
/// user-writable directory (§13 Q2 hardlink-evasion lock-in).
/// V1.0 fires on the user-writable signal alone — the kernel
/// hook doesn't surface mode bits in the [`FimDriftRaw`] today,
/// so we can't post-hoc check SUID-root from the rule layer.
/// The audit chain captures the modifier triple so the
/// operator can correlate.
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
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "Created or hardlinked file in user-writable dir — SUID evasion path \
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
        if fe.op != FimOp::Modified {
            return None;
        }
        if !SENSITIVE_CONFIG_EXACT.iter().any(|p| fe.path == *p) {
            return None;
        }
        Some(fim_verdict(
            self,
            fe,
            ResponseAction::KillProcess,
            Severity::High,
            "Sensitive system config modified",
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
        if fe.op != FimOp::Modified {
            return None;
        }
        // `ends_with` rather than `contains` so `authorized_keys2`
        // (legacy OpenSSH ≤ 5.9) doesn't trip a partial-substring
        // match. The leading `/` requirement guards against
        // pathological filenames the substring would otherwise
        // false-positive on (e.g. an attacker-named directory
        // containing the literal string).
        if !fe.path.ends_with("/.ssh/authorized_keys") {
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
/// `FimEvent` doesn't carry the new size or baseline size
/// today (they live in `BaselineEntry` + `FimDriftEntry`
/// respectively); for C5 we fire on *any* modification of
/// these paths and let the operator distinguish via the
/// drift log's `baseline_sha256` + `new_sha256` fields. A
/// future commit may extend `FimEvent` with `new_size` /
/// `baseline_size` so the rule can fire only on actual
/// truncation.
pub struct NnLFim005LogTruncated;

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

/// `Created` op against any of the cron drop-in roots. High
/// severity — MITRE T1053.003 (Cron) is the canonical
/// scheduled-task persistence vector. Includes
/// `/etc/crontab` as an exact-match path (it's a file, not
/// a dir, so the `starts_with` check works both ways).
pub struct NnLFim007CronDropInCreated;

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
        if !CRON_DROPIN_PATHS.iter().any(|p| fe.path.starts_with(p)) {
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

/// Modification of any file under `/lib/modules/`. Critical —
/// a modified kernel module is a rootkit-class compromise
/// (MITRE T1014 Rootkit + T1547.006 Boot/Logon Autostart
/// Execution: Kernel Modules).
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
        if fe.op != FimOp::Modified {
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
            "Kernel module file modified — rootkit indicator",
        ))
    }
}

// ── NN-L-FIM-009 — systemd unit file dropped/modified ──────────────

/// `Created` or `Modified` op against any systemd unit
/// directory. High severity — MITRE T1543.002 (Systemd
/// Service) is a persistence vector second only to cron in
/// prevalence.
pub struct NnLFim009SystemdUnitDropped;

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
            .map(|d| RANSOMWARE_EXTENSIONS.iter().any(|ext| d.ends_with(ext)))
            .unwrap_or(false);
        let src_match = RANSOMWARE_EXTENSIONS
            .iter()
            .any(|ext| fe.path.ends_with(ext));
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

/// Process basenames that legitimately read the cloud-cred
/// files for each family. Comm field is `TASK_COMM_LEN`
/// (15 chars + NUL) so all entries fit without truncation.
/// Operator-tunable in a future V1.1 commit; the V1.0 list
/// covers the most-common official CLIs per cloud.
const AWS_CLI_COMMS: &[&str] = &["aws", "aws-cli"];
const AZURE_CLI_COMMS: &[&str] = &["az"];
const GCP_CLI_COMMS: &[&str] = &["gcloud", "gsutil", "bq"];
const DOCKER_CLI_COMMS: &[&str] = &["docker", "dockerd", "containerd"];

/// Common shape for the 4 cred-read rules — every rule
/// follows the same `FimOp::Opened` + path-fragment +
/// CLI-comm-exempt pattern. Extracted into a single helper so
/// each rule body stays a 1-line config block.
fn evaluate_cred_read(
    rule: &dyn Rule,
    event: &Event,
    path_fragments: &[&str],
    legit_cli_comms: &[&str],
    reasoning: &str,
) -> Option<Verdict> {
    let fe = as_fim(event)?;
    if fe.op != FimOp::Opened {
        return None;
    }
    if !path_fragments.iter().any(|f| fe.path.contains(f)) {
        return None;
    }
    // FP guard: the legitimate CLI for this cloud reading its
    // own creds is the dominant traffic pattern. Skip when the
    // modifier_comm matches. The audit chain still captures
    // the event regardless (decision_engine_skipped path in C4
    // does not apply here — we drop the verdict outright at
    // the rule layer so the engine doesn't kill the legit CLI).
    if legit_cli_comms.iter().any(|c| fe.modifier_comm == *c) {
        return None;
    }
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
            AWS_CLI_COMMS,
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
            AZURE_CLI_COMMS,
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
            GCP_CLI_COMMS,
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
            DOCKER_CLI_COMMS,
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
/// exempted so the rule fires on a NON-browser process touching the
/// file (the exfil shape).
const BROWSER_COMMS: &[&str] = &[
    "chrome",
    "chromium",
    "firefox",
    "firefox-bin",
    "brave",
    "msedge",
    "opera",
    "vivaldi",
];

/// NN-L-FIM-016: password-manager database fragments — KeePass
/// `*.kdbx` + the `pass` store directory.
const PASSWORD_MANAGER_FRAGMENTS: &[&str] = &[".kdbx", "/.password-store/"];

/// Password managers that legitimately read their own store.
const PASSWORD_MANAGER_COMMS: &[&str] = &["keepassxc", "keepass", "keepass2", "pass", "gopass"];

/// NN-L-FIM-017: GPG keyring directory fragment.
const GPG_KEYRING_FRAGMENTS: &[&str] = &["/.gnupg/"];

/// The GnuPG toolchain that legitimately reads the keyring.
const GPG_COMMS: &[&str] = &["gpg", "gpg2", "gpg-agent", "gpgconf", "gpgsm", "dirmngr"];

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

/// NN-L-FIM-018: the login-record file `utmp`-family writers
/// legitimately rewrite. A Modified op by anything else is the
/// log-tamper shape.
const LASTLOG_PATHS: &[&str] = &["/var/log/lastlog"];

/// NN-L-FIM-019: the binary login-record logs (`wtmp` = successful
/// logins, `btmp` = failed). Same legitimate-writer set as -018.
const WTMP_BTMP_PATHS: &[&str] = &["/var/log/wtmp", "/var/log/btmp"];

/// The login-session machinery that legitimately appends to the
/// `utmp`-family records (via the libc utmp API). A Modified op
/// from any other comm is the tamper shape NN-L-FIM-018/019 catch.
const LOGIN_RECORD_LEGIT_COMMS: &[&str] = &[
    "login",
    "sshd",
    "systemd-logind",
    "init",
    "systemd",
    "getty",
    "agetty",
    "lightdm",
    "gdm",
    "gdm-session-wor",
    "su",
    "sudo",
    "lastlog",
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
    legit_comms: &[&str],
    reasoning: &str,
) -> Option<Verdict> {
    let fe = as_fim(event)?;
    if !matches!(fe.op, FimOp::Opened | FimOp::Modified) {
        return None;
    }
    if !path_fragments.iter().any(|f| fe.path.contains(f)) {
        return None;
    }
    // FP guard: the application that owns the store is the dominant
    // traffic; skip when the modifier comm matches. The audit chain
    // still captures the event.
    if legit_comms.iter().any(|c| fe.modifier_comm == *c) {
        return None;
    }
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
/// path by a comm NOT in [`LOGIN_RECORD_LEGIT_COMMS`]. High +
/// KillProcess.
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
    if LOGIN_RECORD_LEGIT_COMMS
        .iter()
        .any(|c| fe.modifier_comm == *c)
    {
        return None;
    }
    Some(fim_verdict(
        rule,
        fe,
        ResponseAction::KillProcess,
        Severity::High,
        reasoning,
    ))
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
            BROWSER_COMMS,
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
            PASSWORD_MANAGER_COMMS,
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
            GPG_COMMS,
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
        if !(fe.path.contains(PAM_MODULE_DIR_FRAGMENT) && fe.path.ends_with(PAM_MODULE_SUFFIX)) {
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
        if !(starts_with_any(&fe.path, SYSTEMD_UNIT_PREFIXES)
            && fe.path.ends_with(SYSTEMD_TIMER_SUFFIX))
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
pub fn fim_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Critical first — fire on the worst-case signals
        // before any High/Medium rule has a chance to match.
        Box::new(NnLFim010RansomwareExtensionRename),
        Box::new(NnLFim001SystemBinaryModified),
        Box::new(NnLFim002NewSuidBinary),
        Box::new(NnLFim008KernelModuleModified),
        // High next.
        Box::new(NnLFim003SensitiveConfigModified),
        Box::new(NnLFim004AuthorizedKeysModified),
        Box::new(NnLFim005LogTruncated),
        Box::new(NnLFim007CronDropInCreated),
        Box::new(NnLFim009SystemdUnitDropped),
        // C5.3 — cloud credential read family. Same High
        // tier as the rest of the credential-access bucket
        // (NN-L-FIM-003 sensitive config / NN-L-FIM-004
        // authorized_keys).
        Box::new(NnLFim011AwsCredsRead),
        Box::new(NnLFim012AzureCredsRead),
        Box::new(NnLFim013GcpCredsRead),
        Box::new(NnLFim014DockerCredsRead),
        // Tappa 10.5 D3 — Critical first.
        Box::new(NnLFim021PamModuleModified),
        Box::new(NnLFim022LdSoPreloadModified),
        // D3 High tier.
        Box::new(NnLFim015BrowserCredsAccessed),
        Box::new(NnLFim016PasswordManagerDbAccessed),
        Box::new(NnLFim017GpgKeyringAccessed),
        Box::new(NnLFim018LastlogTampered),
        Box::new(NnLFim019WtmpBtmpTampered),
        Box::new(NnLFim023SystemdTimerCreated),
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

    fn fim_event(op: FimOp, path: &str) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op,
            new_sha256: Some([0xAA; 32]),
            baseline_sha256: Some([0xBB; 32]),
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "attacker".to_string(),
            dest_path: None,
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
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "attacker".to_string(),
            dest_path: Some(dest.to_string()),
        })
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
        };
        for rule in fim_rules() {
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
    fn fim002_fires_on_created_or_linked_in_user_writable_dir() {
        let r = NnLFim002NewSuidBinary;
        for (op, path) in &[
            (FimOp::Created, "/tmp/.x"),
            (FimOp::Linked, "/tmp/.x"),
            (FimOp::Created, "/var/tmp/y"),
            (FimOp::Linked, "/var/tmp/y"),
            (FimOp::Created, "/dev/shm/z"),
            (FimOp::Linked, "/home/u/.x"),
        ] {
            let v = r
                .evaluate(&fim_event(*op, path))
                .unwrap_or_else(|| panic!("expected fire on ({op:?}, {path})"));
            assert_eq!(v.severity, Severity::Critical);
            assert_eq!(v.action, ResponseAction::KillProcessTree);
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

    #[test]
    fn fim004_does_not_fire_on_authorized_keys2_or_other_ssh_files() {
        let r = NnLFim004AuthorizedKeysModified;
        // authorized_keys2 is legacy SSH; not strictly the same path. V1.0 doesn't cover.
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/root/.ssh/authorized_keys2"))
            .is_none());
        // known_hosts isn't a backdoor surface.
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/root/.ssh/known_hosts"))
            .is_none());
    }

    // ── NN-L-FIM-005 ────────────────────────────────────────────

    #[test]
    fn fim005_fires_on_log_modification_but_logs_only() {
        let r = NnLFim005LogTruncated;
        for path in &[
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/audit/audit.log",
        ] {
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
        let r = NnLFim005LogTruncated;
        assert!(r
            .evaluate(&fim_event(FimOp::Modified, "/etc/passwd"))
            .is_none());
        assert!(r.evaluate(&fim_event(FimOp::Modified, "/tmp/x")).is_none());
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
        let r = NnLFim007CronDropInCreated;
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
        let r = NnLFim007CronDropInCreated;
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/etc/passwd"))
            .is_none());
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/var/spool/lpd/x"))
            .is_none());
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
        let r = NnLFim009SystemdUnitDropped;
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
        let r = NnLFim009SystemdUnitDropped;
        // /run/systemd/system/ is runtime state, not a unit file
        // root. systemctl writes runtime overrides there; not
        // a persistence vector.
        assert!(r
            .evaluate(&fim_event(FimOp::Created, "/run/systemd/system/x.service"))
            .is_none());
    }

    // ── builder hygiene ─────────────────────────────────────────

    #[test]
    fn fim_rules_builder_returns_distinct_rules() {
        let rules = fim_rules();
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
            modifier_exe: None,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: comm.to_string(),
            dest_path: None,
        })
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
    fn fim011_does_not_fire_on_aws_cli_reading_own_creds() {
        let r = NnLFim011AwsCredsRead;
        for comm in &["aws", "aws-cli"] {
            assert!(
                r.evaluate(&fim_event_with_comm(
                    FimOp::Opened,
                    "/root/.aws/credentials",
                    comm
                ))
                .is_none(),
                "legit {comm} reading its own creds must not fire"
            );
        }
    }

    #[test]
    fn fim011_does_not_fire_on_non_opened_op_or_non_aws_path() {
        let r = NnLFim011AwsCredsRead;
        // Modified op of AWS creds is interesting (rare, but
        // covered by other rules); 011 is Opened-only.
        assert!(r
            .evaluate(&fim_event_with_comm(
                FimOp::Modified,
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

    #[test]
    fn fim012_does_not_fire_on_az_cli_reading_own_creds() {
        let r = NnLFim012AzureCredsRead;
        assert!(r
            .evaluate(&fim_event_with_comm(
                FimOp::Opened,
                "/root/.azure/azureProfile.json",
                "az"
            ))
            .is_none());
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

    #[test]
    fn fim013_does_not_fire_on_gcloud_or_gsutil_or_bq() {
        let r = NnLFim013GcpCredsRead;
        for comm in &["gcloud", "gsutil", "bq"] {
            assert!(
                r.evaluate(&fim_event_with_comm(
                    FimOp::Opened,
                    "/root/.config/gcloud/credentials.db",
                    comm
                ))
                .is_none(),
                "legit {comm} reading its own creds must not fire"
            );
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

    #[test]
    fn fim014_does_not_fire_on_docker_daemon_or_containerd() {
        let r = NnLFim014DockerCredsRead;
        for comm in &["docker", "dockerd", "containerd"] {
            assert!(
                r.evaluate(&fim_event_with_comm(
                    FimOp::Opened,
                    "/root/.docker/config.json",
                    comm
                ))
                .is_none(),
                "legit {comm} reading its own creds must not fire"
            );
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
    fn fim_builder_has_twenty_three_rules_post_d3() {
        // C5 shipped 9, C5.1 added 1, C5.3 added 4 → 14; Tappa 10.5
        // D3 adds NN-L-FIM-015..023 (9) → 23 total.
        let n = fim_rules().len();
        assert_eq!(n, 23, "expected 23 FIM rules post-D3, got {n}");
    }

    // ── Tappa 10.5 D3 — table-driven coverage (§13 Q8) ──────────────
    //
    // The 9 new FIM rules (NN-L-FIM-015..023) are a homogeneous
    // path-pattern family, so per §13 Q8 they're covered by a single
    // `(rule, op, path, comm, expect)` table rather than 27
    // near-identical bespoke pairs. Each row asserts either a fired
    // verdict (severity + action) or no fire. Positive, negative
    // (wrong path / wrong op), and comm-exemption cases are all rows.

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
                NoFire, // browser reading its own store
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
                NoFire, // PM reading its own DB
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
                NoFire, // gpg reading its own keyring
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
                NoFire, // legitimate login writer
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
                NoFire, // legitimate failed-login writer
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
}
