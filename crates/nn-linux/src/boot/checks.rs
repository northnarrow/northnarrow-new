//! The preflight checks the attach depends on (Wave 4 restructure, R11b, lab
//! PR 262): each runs its check against the host and records its step in the
//! boot sequence only when the check passed.
//!
//! [`BootSequence::done`] refuses these steps ([`BootStep::is_checked`]), so
//! [`BootSequence::verify_integrity`] — the one constructor of
//! [`super::IntegrityVerified`], which the eBPF object's load, the pins and
//! the attaches take — is reached only through them, in a start that ran
//! every one of them and was refused by none. What each returns is what its
//! caller, the agent's preflight and integrity phases, logs, signs and
//! refuses on; a check that refuses records nothing.

use std::path::{Path, PathBuf};

use super::continuity;
use super::lsm::{self, BpfLsm, LsmGate};
use super::{BootOrderError, BootSequence, BootStep};
use crate::anti_tamper::btf_revalidate::{self, ResolveOutcome};
use crate::audit_preflight::{self, AuditPreflight};
use crate::install_manifest::{self, BootHistory, IntegrityOutcome};
use crate::response::caps_preflight::{self as caps, BootGate, CapsReading};

/// What a check that returns no outcome of its own decided.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// The check passed: its step is recorded.
    Passed,
    /// The check refuses the start: why (nothing recorded).
    Refused(String),
}

/// Lab PR 265 (review #466 F4-bis; the review of #468, R1–R3): the
/// agent's view of its own directories is the one it had.
///
/// - In the agent's own mount table ([`continuity::OWN_MOUNTINFO`], read
///   as bytes by [`crate::mountinfo`]), no mount at or under the agent's
///   directories but a bind of a directory onto itself (the unit's
///   `ReadWritePaths=`; [`continuity::mounts_over`]): the configuration
///   directory and the state directory always (the host's roots, review
///   #466 F3), and the directories of the files the operator's
///   configuration names (`configured`: the key's, the audit log's, the
///   identity's, the chains'). Another directory or file bound there,
///   another filesystem (a tmpfs, a runtime drop-in's
///   `TemporaryFileSystem=`): each hides the files the agent had. A mount
///   above them (a separate `/var`) is not judged there. A line the table
///   does not hold in the kernel's shape refuses only when it may concern
///   those directories.
/// - One bpffs at `/sys/fs/bpf`, nothing stacked on it or over the pin
///   root ([`continuity::bpffs_findings`]): the pins are the next proof.
/// - The previous agent's pins, when there are some: the configuration
///   and the state directory this start sees are the inodes that agent
///   protected ([`continuity::view_findings`]) — what no view of the
///   filesystem can change: a copy bound over an ancestor, a rename above
///   them, another root show other inodes.
///
/// A table that cannot be read refuses too.
pub fn agent_mounts(
    boot: &mut BootSequence,
    configured: &[&Path],
) -> Result<Verdict, BootOrderError> {
    let table = std::fs::read(continuity::OWN_MOUNTINFO).map_err(|e| e.to_string());
    let config = Path::new(crate::anti_tamper::filesystem::CONFIG_DIR);
    let state = Path::new(crate::anti_tamper::filesystem::STATE_DIR);
    let mut dirs: Vec<&Path> = vec![config, state];
    dirs.extend_from_slice(configured);
    let pin_root = Path::new(crate::anti_tamper::DEFAULT_BPFFS_ROOT);
    agent_mounts_decided(
        boot,
        table,
        &continuity::spelled(&dirs),
        pin_root,
        &continuity::previous_agent(pin_root),
        &[config.to_path_buf(), state.to_path_buf()],
    )
}

/// [`agent_mounts`] on the table `table`, the previous agent `previous`
/// and the agent's own directories `own` (this crate's tests).
fn agent_mounts_decided(
    boot: &mut BootSequence,
    table: Result<Vec<u8>, String>,
    dirs: &[PathBuf],
    pin_root: &Path,
    previous: &continuity::PreviousAgent,
    own: &[PathBuf],
) -> Result<Verdict, BootOrderError> {
    let table = match table {
        Ok(t) => crate::mountinfo::parse(&t),
        Err(why) => {
            return Ok(Verdict::Refused(format!(
                "{}: {why} — the mounts over the agent's directories cannot be checked",
                continuity::OWN_MOUNTINFO
            )))
        }
    };
    if !table
        .entries
        .iter()
        .any(|m| m.mount_point == Path::new("/"))
    {
        return Ok(Verdict::Refused(format!(
            "{} names no root mount — the mounts over the agent's directories cannot be checked",
            continuity::OWN_MOUNTINFO
        )));
    }
    let found = continuity::mounts_over(&table, dirs);
    if !found.is_empty() {
        return Ok(Verdict::Refused(format!(
            "a mount hides the agent's own files: {}. The start would read, mint and sign in what \
             was laid over them, so it is refused before anything is read or written. Remove the \
             mount (or the drop-in that makes it: BindPaths=, TemporaryFileSystem=, \
             BindReadOnlyPaths=); the agent's directories must not be mount points of their own \
             (a separate /var, or /var/lib, is fine)",
            found.join("; ")
        )));
    }
    let found = continuity::bpffs_findings(&table, pin_root);
    if !found.is_empty() {
        return Ok(Verdict::Refused(format!(
            "the bpffs of the previous agent's pins is not the one alone at /sys/fs/bpf: {}. A \
             mount stacked there hides the pins, the kernel's record of what the previous agent \
             protected; remove it",
            found.join("; ")
        )));
    }
    let found = continuity::view_findings(previous, own);
    if !found.is_empty() {
        return Ok(Verdict::Refused(format!(
            "the agent's directories are not the ones the previous agent protected: {}. A start \
             in another view would read, mint and sign in it. Undo the mount or the rename; when \
             the change is the operator's own, stop the units and remove the pins first \
             (docs/operator/INSTALL_UPGRADE_UNINSTALL.md, \"Re-keying the agent\")",
            found.join("; ")
        )));
    }
    boot.passed(BootStep::AgentMounts)?;
    Ok(Verdict::Passed)
}

/// Lab PR 265 (review #466 F4-bis; the review of #468, R2 and R8): the
/// agent's signing key is not minted where an earlier identity is on
/// record.
///
/// - The key there — in any form: a key that is not one is the audit
///   check's refusal (review #466 F4) — or nothing says this install had
///   one ([`continuity::prior_identity`]: the key's public half, the
///   install's id, a written head anchor, a signed row of a chain, its
///   manifest or its archives; any lookup that fails otherwise than "not
///   found"): a first install, which mints it. A key absent where any of
///   that is found was removed or is hidden: refused, nothing minted.
/// - The previous agent's pins, when there are some: a start that runs
///   the binary that agent protected (the installed one) is its restart —
///   its key must be in a directory that agent protected and there
///   ([`continuity::restart_key_findings`]): a restart never mints.
pub fn signing_identity(
    boot: &mut BootSequence,
    paths: &continuity::IdentityPaths,
) -> Result<Verdict, BootOrderError> {
    signing_identity_decided(
        boot,
        paths,
        &continuity::previous_agent(Path::new(crate::anti_tamper::DEFAULT_BPFFS_ROOT)),
        Path::new("/proc/self/exe"),
    )
}

/// [`signing_identity`] against the previous agent `previous` and the
/// binary `exe` (this crate's tests).
fn signing_identity_decided(
    boot: &mut BootSequence,
    paths: &continuity::IdentityPaths,
    previous: &continuity::PreviousAgent,
    exe: &Path,
) -> Result<Verdict, BootOrderError> {
    let restart = continuity::restart_key_findings(previous, exe, &paths.signing_key);
    if !restart.is_empty() {
        return Ok(Verdict::Refused(format!(
            "{}. Nothing is minted. Put the key back, or undo what changed its path (a drop-in \
             redefining ExecStart=); to re-key on purpose, retire the install's identity \
             (docs/operator/INSTALL_UPGRADE_UNINSTALL.md, \"Re-keying the agent\": the agent \
             that refuses to start)",
            restart.join("; ")
        )));
    }
    if continuity::key_absent(&paths.signing_key) {
        let evidence = continuity::prior_identity(paths);
        if !evidence.is_empty() {
            return Ok(Verdict::Refused(continuity::refusal_detail(
                &paths.signing_key,
                &evidence,
            )));
        }
    }
    boot.passed(BootStep::SigningIdentity)?;
    Ok(Verdict::Passed)
}

/// The embedded eBPF object is real and intact
/// ([`crate::sensors::ebpf_object::preflight`]).
pub fn ebpf_object(boot: &mut BootSequence) -> Result<Verdict, BootOrderError> {
    match crate::sensors::ebpf_object::preflight() {
        Ok(()) => {
            boot.passed(BootStep::EbpfObject)?;
            Ok(Verdict::Passed)
        }
        Err(e) => Ok(Verdict::Refused(format!("{e:#}"))),
    }
}

/// The state directory ([`crate::anti_tamper::filesystem::STATE_DIR`]),
/// and the agent's own entries in it, are not symbolic links
/// ([`crate::anti_tamper::filesystem::refuse_linked_state_dir`]). Review
/// #466 F3: the host's directory, not one the caller names.
pub fn state_dir(boot: &mut BootSequence) -> Result<Verdict, BootOrderError> {
    state_dir_in(boot, Path::new(crate::anti_tamper::filesystem::STATE_DIR))
}

/// [`state_dir`] for `dir` (this crate's tests).
fn state_dir_in(boot: &mut BootSequence, dir: &Path) -> Result<Verdict, BootOrderError> {
    match crate::anti_tamper::filesystem::refuse_linked_state_dir(dir) {
        Ok(()) => {
            boot.passed(BootStep::StateDir)?;
            Ok(Verdict::Passed)
        }
        Err(e) => Ok(Verdict::Refused(format!("{e:#}"))),
    }
}

/// The kernel offsets the programs read, resolved from the running kernel's
/// BTF ([`btf_revalidate::resolve_offsets`]): every outcome but
/// [`ResolveOutcome::Refuse`] passes — a layout that differs from the build
/// kernel's is resolved, a kernel without BTF attaches no LSM hook (the
/// attach decides). Publishing the values for the load is the caller's.
pub fn btf_offsets(boot: &mut BootSequence) -> Result<ResolveOutcome, BootOrderError> {
    let outcome = btf_revalidate::resolve_offsets();
    btf_offsets_decided(boot, &outcome)?;
    Ok(outcome)
}

fn btf_offsets_decided(
    boot: &mut BootSequence,
    outcome: &ResolveOutcome,
) -> Result<(), BootOrderError> {
    if !matches!(outcome, ResolveOutcome::Refuse(_)) {
        boot.passed(BootStep::BtfOffsets)?;
    }
    Ok(())
}

/// This thread's effective capabilities against what the response needs
/// ([`caps::read_effective`], [`caps::boot_gate`]): [`BootGate::Start`]
/// passes (its degradations are the caller's to sign). Detect-only is the
/// command line's `--detect-only` (`cli_detect_only`) or the process's
/// environment (`NN_DETECT_ONLY`, `NORTHNARROW_DRY_RUN`), read here (review
/// #466 F3), as the response reads it.
pub fn capabilities(
    boot: &mut BootSequence,
    cli_detect_only: bool,
) -> Result<(CapsReading, BootGate), BootOrderError> {
    let detect_only = cli_detect_only || nn_core::response::config::detect_only_env().is_some();
    let reading = caps::read_effective();
    let gate = capabilities_decided(boot, &reading, detect_only)?;
    Ok((reading, gate))
}

fn capabilities_decided(
    boot: &mut BootSequence,
    reading: &CapsReading,
    detect_only: bool,
) -> Result<BootGate, BootOrderError> {
    let gate = caps::boot_gate(reading, detect_only);
    if matches!(gate, BootGate::Start { .. }) {
        boot.passed(BootStep::Capabilities)?;
    }
    Ok(gate)
}

/// What [`install_manifest`] found.
#[derive(Debug)]
pub struct ManifestCheck {
    /// The running binaries against the manifest.
    pub outcome: IntegrityOutcome,
    /// External audit DEP-009: what the audit chain says about this
    /// install's earlier boots — read only when the manifest is missing.
    pub history: BootHistory,
    /// Why that history could not be read (the chain unreadable): it then
    /// counts as [`BootHistory::Unknown`].
    pub history_error: Option<String>,
    /// The start is refused ([`IntegrityOutcome::is_fatal`]).
    pub fatal: bool,
}

/// The running binaries against the install manifest at `manifest`
/// ([`install_manifest::check`]): every outcome passes but a fatal one — a
/// mismatch, an unreadable manifest, or a missing one after a verified boot
/// of this install (DEP-009, the signed chain at `audit_log` the sentinel)
/// — unless the process's environment has
/// [`install_manifest::ALLOW_UNVERIFIED_ENV`]`=1`. Review #466 F3: the
/// binary compared is the running one (`std::env::current_exe`, else
/// `/proc/self/exe`) and the override the environment's, not what the
/// caller names.
pub fn install_manifest(
    boot: &mut BootSequence,
    manifest: &Path,
    audit_log: &Path,
) -> Result<ManifestCheck, BootOrderError> {
    let own_exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
    let allow = std::env::var(install_manifest::ALLOW_UNVERIFIED_ENV).ok();
    install_manifest_for(boot, manifest, &own_exe, audit_log, allow.as_deref())
}

/// [`install_manifest`] for the binary `own_exe` (this crate's tests).
fn install_manifest_for(
    boot: &mut BootSequence,
    manifest: &Path,
    own_exe: &Path,
    audit_log: &Path,
    allow_unverified: Option<&str>,
) -> Result<ManifestCheck, BootOrderError> {
    let outcome =
        install_manifest::check(manifest, own_exe, crate::sensors::ebpf_object::OBJECT_SHA);
    // External audit DEP-009: a missing manifest is a removal once a boot
    // of this install verified against it — the signed chain is the
    // sentinel, read (only in that case) before the decision.
    let (history, history_error) = match &outcome {
        IntegrityOutcome::NoManifest { .. } => {
            match crate::audit::verified_boot_recorded::<crate::chain_host_linux::LinuxHost>(
                audit_log,
            ) {
                Ok(true) => (BootHistory::VerifiedBefore, None),
                Ok(false) => (BootHistory::NeverVerified, None),
                Err(e) => (BootHistory::Unknown, Some(format!("{e:#}"))),
            }
        }
        _ => (BootHistory::NeverVerified, None),
    };
    install_manifest_decided(boot, outcome, history, history_error, allow_unverified)
}

fn install_manifest_decided(
    boot: &mut BootSequence,
    outcome: IntegrityOutcome,
    history: BootHistory,
    history_error: Option<String>,
    allow_unverified: Option<&str>,
) -> Result<ManifestCheck, BootOrderError> {
    let fatal = outcome.is_fatal(allow_unverified, history);
    if !fatal {
        boot.passed(BootStep::InstallManifest)?;
    }
    Ok(ManifestCheck {
        outcome,
        history,
        history_error,
        fatal,
    })
}

/// What [`audit_log`] found.
#[derive(Debug)]
pub struct AuditCheck {
    /// The log's writability, read without writing
    /// ([`audit_preflight::preflight_writable`]).
    pub preflight: AuditPreflight,
    /// R11b (lab PR 262): the log's open — its chain read — before the load.
    pub open: AuditOpen,
    /// The start is refused: the log cannot be written, its chain cannot be
    /// opened, or (review #466 F4) the agent's key cannot be loaded, and
    /// `NN_AUDIT_ALLOW_UNWRITABLE=1` is not set.
    pub fatal: bool,
}

/// The audit log's open, before anything is loaded (R11b, lab PR 262; the
/// attest phase opened it after the attach until then).
pub enum AuditOpen {
    /// Opened for append, its chain read (a torn last write repaired and
    /// signed): the attest phase appends the boot's rows to it.
    Open(Box<crate::audit::AuditLog>),
    /// Not opened before the attach: the previous agent's pinned hooks close
    /// the log or the agent's key to this process, whose early registration
    /// failed — only this boot's attach registers it. The attest phase opens
    /// it (as it did before R11b), and a failure refuses the start there.
    Deferred(String),
    /// The agent's key cannot be loaded — a file there that is not a key
    /// (corrupted, empty, a bind mount of `/dev/null` or another file that
    /// is not a regular one over the name, unreadable), or an absent one
    /// that could not be minted: no row can be signed. Refused like an
    /// unwritable log unless `NN_AUDIT_ALLOW_UNWRITABLE=1` (review #466 F4:
    /// the start ran unaudited, with only a WARN, until then); the refusal
    /// is the journal's alone. An absent key is minted only at a first
    /// install: where an earlier identity is on record, [`signing_identity`]
    /// refused the start before (lab PR 265, review #466 F4-bis).
    NoKey(String),
    /// The log cannot be opened: a line before the end is not a row (the
    /// chain is broken), or the file cannot be opened for writing (under
    /// the override). Why.
    Failed(String),
    /// Not tried: the preflight found the log unwritable without the
    /// override.
    NotTried,
}

impl AuditOpen {
    /// The log, when it is open: what a refusal after the open signs into
    /// (one writer of the chain).
    pub fn log_mut(&mut self) -> Option<&mut crate::audit::AuditLog> {
        match self {
            AuditOpen::Open(log) => Some(log),
            _ => None,
        }
    }
}

impl std::fmt::Debug for AuditOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditOpen::Open(log) => write!(f, "Open(rows: {})", log.rows()),
            AuditOpen::Deferred(why) => f.debug_tuple("Deferred").field(why).finish(),
            AuditOpen::NoKey(why) => f.debug_tuple("NoKey").field(why).finish(),
            AuditOpen::Failed(why) => f.debug_tuple("Failed").field(why).finish(),
            AuditOpen::NotTried => f.write_str("NotTried"),
        }
    }
}

/// The audit log at `path` can be written: opened for append without
/// writing, or its directory able to take it
/// ([`audit_preflight::preflight_writable`]; `closed_by_previous_hooks`:
/// the early registration in the pinned `PROTECTED_PIDS` failed, so a
/// permission error is left to the attest phase); then (R11b, lab PR 262)
/// opened with the agent's key at `signing_key` and the start's `agent_id`
/// ([`crate::audit::AuditLog::open`]: its chain read, a broken one refused).
/// An unwritable log, one that cannot be opened, or a key that cannot be
/// loaded (review #466 F4; an absent one is minted, at a first install
/// only: [`signing_identity`]) refuses the start unless
/// the process's environment has
/// [`crate::audit::AUDIT_ALLOW_UNWRITABLE_ENV`]`=1` (read here, review #466
/// F3).
pub fn audit_log(
    boot: &mut BootSequence,
    path: &Path,
    signing_key: &Path,
    agent_id: [u8; 16],
    closed_by_previous_hooks: bool,
) -> Result<AuditCheck, BootOrderError> {
    let allow = std::env::var(crate::audit::AUDIT_ALLOW_UNWRITABLE_ENV).ok();
    audit_log_with(
        boot,
        path,
        signing_key,
        agent_id,
        closed_by_previous_hooks,
        allow.as_deref(),
    )
}

/// [`audit_log`] with the override `allow_unwritable` (this crate's tests).
fn audit_log_with(
    boot: &mut BootSequence,
    path: &Path,
    signing_key: &Path,
    agent_id: [u8; 16],
    closed_by_previous_hooks: bool,
    allow_unwritable: Option<&str>,
) -> Result<AuditCheck, BootOrderError> {
    let preflight = audit_preflight::preflight_writable(path, closed_by_previous_hooks);
    let allowed = !crate::audit::audit_failure_is_fatal(allow_unwritable);
    let open = match &preflight {
        AuditPreflight::Unwritable(_) if !allowed => AuditOpen::NotTried,
        AuditPreflight::Deferred(why) => AuditOpen::Deferred(why.clone()),
        _ => open_audit_log(path, signing_key, agent_id, closed_by_previous_hooks),
    };
    let fatal = !allowed
        && (matches!(preflight, AuditPreflight::Unwritable(_))
            || matches!(open, AuditOpen::Failed(_) | AuditOpen::NoKey(_)));
    if !fatal {
        boot.passed(BootStep::AuditWritable)?;
    }
    Ok(AuditCheck {
        preflight,
        open,
        fatal,
    })
}

/// [`AuditLog::open`](crate::audit::AuditLog::open) with the agent's key,
/// as the attest phase opened it.
fn open_audit_log(
    path: &Path,
    signing_key: &Path,
    agent_id: [u8; 16],
    closed_by_previous_hooks: bool,
) -> AuditOpen {
    // A permission error while the previous hooks may close the agent's
    // files to this process: the attach registers it, the attest phase opens
    // the log (lab PR 218's deferral, for the key and the log too).
    let closed = |e: &anyhow::Error| {
        closed_by_previous_hooks
            && e.chain().any(|c| {
                c.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
            })
    };
    let key = match crate::keys::AgentSigningKey::load_or_bootstrap(signing_key) {
        Ok(key) => key,
        Err(e) if closed(&e) => {
            return AuditOpen::Deferred(format!(
                "{e:#} (the previous agent's hooks close it to an unregistered process)"
            ))
        }
        Err(e) => return AuditOpen::NoKey(format!("{e:#}")),
    };
    match crate::audit::AuditLog::open(path, key, agent_id) {
        Ok(log) => AuditOpen::Open(Box::new(log)),
        Err(e) if closed(&e) => AuditOpen::Deferred(format!(
            "{e:#} (the previous agent's hooks close it to an unregistered process)"
        )),
        Err(e) => AuditOpen::Failed(format!("{e:#}")),
    }
}

/// `bpf` in the LSMs the kernel runs (`/sys/kernel/security/lsm`;
/// [`lsm::gate`]): every outcome but [`LsmGate::Refuse`] passes — the
/// degraded-mode opt-in and an unreadable list go on,
/// signed by the caller. Review #466 F3: the host's list, under `/`, and
/// the opt-in the process's environment's
/// ([`lsm::allow_degraded_from_env`]).
pub fn bpf_lsm(boot: &mut BootSequence) -> Result<(BpfLsm, LsmGate), BootOrderError> {
    bpf_lsm_in(boot, Path::new("/"), lsm::allow_degraded_from_env())
}

/// [`bpf_lsm`] for the list under `root` (this crate's tests).
fn bpf_lsm_in(
    boot: &mut BootSequence,
    root: &Path,
    allow_degraded: bool,
) -> Result<(BpfLsm, LsmGate), BootOrderError> {
    let state = lsm::read_in(root);
    let gate = lsm::gate(&state, allow_degraded);
    if !matches!(gate, LsmGate::Refuse { .. }) {
        boot.passed(BootStep::BpfLsm)?;
    }
    Ok((state, gate))
}

/// Review #466 F6: the bpffs pin root the load pins into
/// ([`crate::anti_tamper::pin_root_refusal`], ATP-007): a symbolic link, or
/// anything but a directory, refused the start only after the load, from
/// the deny hooks' attach — now before it, unless the degraded-mode opt-in
/// ([`lsm::allow_degraded_from_env`]; the attach then counts it as a failed
/// protection step, signed, as before).
pub fn pin_root(boot: &mut BootSequence) -> Result<Verdict, BootOrderError> {
    pin_root_decided(
        boot,
        crate::anti_tamper::pin_root_refusal(),
        lsm::allow_degraded_from_env(),
    )
}

fn pin_root_decided(
    boot: &mut BootSequence,
    refusal: Option<String>,
    allow_degraded: bool,
) -> Result<Verdict, BootOrderError> {
    match refusal {
        Some(why) if !allow_degraded => Ok(Verdict::Refused(why)),
        _ => {
            boot.passed(BootStep::PinRoot)?;
            Ok(Verdict::Passed)
        }
    }
}

/// Review #466 F6: the kernel's BTF, `/sys/kernel/btf/vmlinux`: every deny
/// hook's attach resolves its hook against it, so without it none attaches
/// (review 53: a kernel built without it, or a tmpfs over
/// `/sys/kernel/btf`). The deny hooks' shortfall refused the start only
/// after the load, which pins the maps — now before it, unless the
/// degraded-mode opt-in ([`lsm::allow_degraded_from_env`]). A file there
/// that does not parse is the BTF offsets' refusal ([`btf_offsets`]).
pub fn vmlinux_btf(boot: &mut BootSequence) -> Result<Verdict, BootOrderError> {
    vmlinux_btf_in(boot, Path::new("/"), lsm::allow_degraded_from_env())
}

/// [`vmlinux_btf`] for the BTF under `root` (this crate's tests).
fn vmlinux_btf_in(
    boot: &mut BootSequence,
    root: &Path,
    allow_degraded: bool,
) -> Result<Verdict, BootOrderError> {
    let path = root.join("sys/kernel/btf/vmlinux");
    let missing = match std::fs::metadata(&path) {
        Ok(m) if m.is_file() && m.len() > 0 => None,
        Ok(_) => Some(format!("{} is empty or not a file", path.display())),
        Err(e) => Some(format!("{}: {e}", path.display())),
    };
    match missing {
        Some(why) if !allow_degraded => Ok(Verdict::Refused(format!(
            "vmlinux BTF unavailable ({why}) — no LSM hook can attach: kernel built without \
             CONFIG_DEBUG_INFO_BTF, or /sys/kernel/btf hidden. Refusing to start with a \
             silently-absent protection; set {}=1 to start degraded.",
            crate::anti_tamper::ALLOW_DEGRADED_ENV
        ))),
        _ => {
            boot.passed(BootStep::VmlinuxBtf)?;
            Ok(Verdict::Passed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::BootPhase;

    fn has(boot: &BootSequence, step: BootStep) -> bool {
        boot.has_done(step)
    }

    /// R11b (lab PR 262): the steps the attach depends on are recorded by
    /// their checks only — `done` refuses each, and without them there is
    /// no proof.
    #[test]
    fn done_refuses_every_checked_step() {
        let mut boot = BootSequence::new();
        for step in BootPhase::Preflight.required() {
            assert!(
                step.is_checked(),
                "{} is required, not checked",
                step.name()
            );
            assert_eq!(
                boot.done(*step),
                Err(BootOrderError::Unchecked { step: step.name() })
            );
        }
        for plain in [
            BootStep::ChainHeads,
            BootStep::Identity,
            BootStep::HostHardening,
        ] {
            assert!(!plain.is_checked());
            boot.done(plain).unwrap();
        }
        let err = boot.verify_integrity().unwrap_err();
        assert!(matches!(err, BootOrderError::Incomplete { .. }), "{err}");
        assert_eq!(boot.phase(), BootPhase::Preflight);
    }

    #[test]
    fn a_linked_state_dir_refuses_and_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("state");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut boot = BootSequence::new();
        assert!(matches!(
            state_dir_in(&mut boot, &link).unwrap(),
            Verdict::Refused(why) if why.contains("symbolic link")
        ));
        assert!(!has(&boot, BootStep::StateDir));
        assert_eq!(state_dir_in(&mut boot, &real).unwrap(), Verdict::Passed);
        assert!(has(&boot, BootStep::StateDir));
        // a missing directory is fine (the attach creates it)
        let mut boot = BootSequence::new();
        assert_eq!(
            state_dir_in(&mut boot, &dir.path().join("absent")).unwrap(),
            Verdict::Passed
        );
    }

    #[test]
    fn a_refused_btf_records_nothing() {
        use crate::anti_tamper::btf_revalidate::RefuseReason;
        let mut boot = BootSequence::new();
        btf_offsets_decided(
            &mut boot,
            &ResolveOutcome::Refuse(RefuseReason::ParseError("garbage".into())),
        )
        .unwrap();
        assert!(!has(&boot, BootStep::BtfOffsets));
        btf_offsets_decided(
            &mut boot,
            &ResolveOutcome::SkippedNoBtf {
                reason: "no /sys/kernel/btf/vmlinux".into(),
            },
        )
        .unwrap();
        assert!(has(&boot, BootStep::BtfOffsets));
    }

    #[test]
    fn a_refused_capability_set_records_nothing() {
        let mut boot = BootSequence::new();
        // no CAP_KILL, enforcing: refused
        let gate = capabilities_decided(
            &mut boot,
            &CapsReading::Read {
                effective: 0,
                note: None,
            },
            false,
        )
        .unwrap();
        assert!(matches!(gate, BootGate::Refuse(_)), "{gate:?}");
        assert!(!has(&boot, BootStep::Capabilities));
        // detect-only starts degraded
        let gate = capabilities_decided(
            &mut boot,
            &CapsReading::Read {
                effective: 0,
                note: None,
            },
            true,
        )
        .unwrap();
        assert!(matches!(gate, BootGate::Start { .. }), "{gate:?}");
        assert!(has(&boot, BootStep::Capabilities));
    }

    #[test]
    fn a_fatal_manifest_records_nothing() {
        let mismatch = || IntegrityOutcome::Mismatch {
            provenance: "attested".into(),
            mismatches: vec![install_manifest::Mismatch {
                name: "northnarrow-agent".into(),
                expected: "aa".into(),
                actual: "bb".into(),
            }],
        };
        let mut boot = BootSequence::new();
        let c = install_manifest_decided(
            &mut boot,
            mismatch(),
            BootHistory::NeverVerified,
            None,
            None,
        )
        .unwrap();
        assert!(c.fatal);
        assert!(!has(&boot, BootStep::InstallManifest));
        // the dev override
        let c = install_manifest_decided(
            &mut boot,
            mismatch(),
            BootHistory::NeverVerified,
            None,
            Some("1"),
        )
        .unwrap();
        assert!(!c.fatal);
        assert!(has(&boot, BootStep::InstallManifest));
    }

    #[test]
    fn a_missing_manifest_after_a_verified_boot_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mut boot = BootSequence::new();
        // no manifest, no chain: a developer run, passed
        let c = install_manifest_for(
            &mut boot,
            &dir.path().join("install-manifest.json"),
            Path::new("/proc/self/exe"),
            &dir.path().join("audit.log"),
            None,
        )
        .unwrap();
        assert!(matches!(c.outcome, IntegrityOutcome::NoManifest { .. }));
        assert_eq!(c.history, BootHistory::NeverVerified);
        assert!(!c.fatal);
        assert!(has(&boot, BootStep::InstallManifest));
        // a chain that cannot be read: the removal is assumed
        std::fs::write(dir.path().join("audit.log"), b"not a row\n").unwrap();
        let mut boot = BootSequence::new();
        let c = install_manifest_for(
            &mut boot,
            &dir.path().join("install-manifest.json"),
            Path::new("/proc/self/exe"),
            &dir.path().join("audit.log"),
            None,
        )
        .unwrap();
        assert_eq!(c.history, BootHistory::Unknown);
        assert!(c.history_error.is_some());
        assert!(c.fatal);
        assert!(!has(&boot, BootStep::InstallManifest));
    }

    #[test]
    fn an_unwritable_audit_log_records_nothing_unless_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("agent.sig.key");
        let not_a_file = dir.path().join("audit.log");
        std::fs::create_dir(&not_a_file).unwrap();
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &not_a_file, &key, [1; 16], false, None).unwrap();
        assert!(matches!(c.preflight, AuditPreflight::Unwritable(_)));
        assert!(matches!(c.open, AuditOpen::NotTried), "{:?}", c.open);
        assert!(c.fatal);
        assert!(!has(&boot, BootStep::AuditWritable));
        assert!(!key.exists(), "nothing opened, no key minted");
        // the override: tried, it fails, the start goes on unaudited
        let c = audit_log_with(&mut boot, &not_a_file, &key, [1; 16], false, Some("1")).unwrap();
        assert!(matches!(c.open, AuditOpen::Failed(_)), "{:?}", c.open);
        assert!(!c.fatal);
        assert!(has(&boot, BootStep::AuditWritable));
    }

    /// R11b (lab PR 262): the audit chain is opened before the load — a
    /// fresh one and a written one open (the attest phase appends to them),
    /// a broken one refuses the start.
    #[test]
    fn the_audit_chain_opens_before_the_load_or_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("agent.sig.key");
        let path = dir.path().join("audit.log");
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &path, &key, [1; 16], false, None).unwrap();
        assert_eq!(c.preflight, AuditPreflight::Writable);
        let AuditOpen::Open(mut log) = c.open else {
            panic!("{:?}", c.open)
        };
        assert!(!c.fatal);
        assert!(has(&boot, BootStep::AuditWritable));
        let build = crate::audit::AgentBuild {
            version: "0.0.0",
            features: Vec::new(),
            bpf_guard_enforce: true,
        };
        log.boot_probe(None, "no-manifest", "none", &build).unwrap();
        drop(log);
        // written: opens again, the next row chains on
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &path, &key, [1; 16], false, None).unwrap();
        let AuditOpen::Open(log) = c.open else {
            panic!("{:?}", c.open)
        };
        assert_eq!(log.rows(), 1);
        drop(log);
        // a line before the end that is not a row: the chain is broken
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{{not a row}}\n{text}")).unwrap();
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &path, &key, [1; 16], false, None).unwrap();
        assert!(
            matches!(c.open, AuditOpen::Failed(ref why) if why.contains("is not an audit row")),
            "{:?}",
            c.open
        );
        assert!(c.fatal);
        assert!(!has(&boot, BootStep::AuditWritable));
        // under the override the start goes on, unaudited
        let c = audit_log_with(&mut boot, &path, &key, [1; 16], false, Some("1")).unwrap();
        assert!(matches!(c.open, AuditOpen::Failed(_)));
        assert!(!c.fatal);
        // a key that cannot be loaded: refused (review #466 F4), below
    }

    /// Review #466 F4: a key file that is not a key — corrupted, empty (what
    /// a bind mount of `/dev/null` reads), `/dev/null` itself, a directory —
    /// refuses the start like an unwritable audit log, and records nothing;
    /// only the override lets it start unaudited. An absent key is minted.
    #[test]
    fn a_key_that_is_there_but_cannot_be_loaded_refuses_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let corrupted = dir.path().join("corrupted.key");
        std::fs::write(&corrupted, "not a key\n").unwrap();
        let empty = dir.path().join("empty.key");
        std::fs::write(&empty, "").unwrap();
        let null = dir.path().join("null.key");
        std::os::unix::fs::symlink("/dev/null", &null).unwrap();
        let directory = dir.path().join("dir.key");
        std::fs::create_dir(&directory).unwrap();
        for key in [&corrupted, &empty, &null, &directory] {
            let mut boot = BootSequence::new();
            let c = audit_log_with(&mut boot, &log, key, [1; 16], false, None).unwrap();
            assert!(matches!(c.open, AuditOpen::NoKey(_)), "{:?}", c.open);
            assert!(c.fatal, "{}", key.display());
            assert!(!has(&boot, BootStep::AuditWritable));
            let c = audit_log_with(&mut boot, &log, key, [1; 16], false, Some("1")).unwrap();
            assert!(matches!(c.open, AuditOpen::NoKey(_)));
            assert!(!c.fatal, "the override");
            assert!(has(&boot, BootStep::AuditWritable));
        }
        assert_eq!(std::fs::read(&empty).unwrap(), b"", "not replaced");
        // absent: minted, as at a first boot
        let fresh = dir.path().join("fresh.key");
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &log, &fresh, [1; 16], false, None).unwrap();
        assert!(matches!(c.open, AuditOpen::Open(_)), "{:?}", c.open);
        assert!(!c.fatal);
        assert!(fresh.is_file());
    }

    /// R11b (lab PR 262): while the previous agent's hooks may close the
    /// agent's files to this process (its early registration failed), a key
    /// it cannot read leaves the open to the attest phase, after the attach
    /// registered it; otherwise the start is refused (review #466 F4).
    #[test]
    fn a_key_closed_to_an_unregistered_start_defers_the_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("agent.sig.key");
        crate::keys::AgentSigningKey::load_or_bootstrap(&key).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&key).is_ok() {
            // root reads it all the same: nothing to show here
            return;
        }
        let path = dir.path().join("audit.log");
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &path, &key, [1; 16], true, None).unwrap();
        assert!(matches!(c.open, AuditOpen::Deferred(_)), "{:?}", c.open);
        assert!(!c.fatal);
        assert!(has(&boot, BootStep::AuditWritable));
        // registered (or no previous hooks): the key is unloadable, refused
        let mut boot = BootSequence::new();
        let c = audit_log_with(&mut boot, &path, &key, [1; 16], false, None).unwrap();
        assert!(matches!(c.open, AuditOpen::NoKey(_)), "{:?}", c.open);
        assert!(c.fatal, "review #466 F4");
    }

    #[test]
    fn a_missing_bpf_lsm_records_nothing_unless_opted_in() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sys/kernel/security")).unwrap();
        std::fs::write(
            dir.path().join(lsm::ACTIVE_LSM_REL),
            "lockdown,capability,landlock,yama,apparmor\n",
        )
        .unwrap();
        let mut boot = BootSequence::new();
        let (state, gate) = bpf_lsm_in(&mut boot, dir.path(), false).unwrap();
        assert!(matches!(state, BpfLsm::Absent { .. }));
        assert!(matches!(gate, LsmGate::Refuse { .. }));
        assert!(!has(&boot, BootStep::BpfLsm));
        let (_, gate) = bpf_lsm_in(&mut boot, dir.path(), true).unwrap();
        assert!(matches!(gate, LsmGate::Degraded { .. }));
        assert!(has(&boot, BootStep::BpfLsm));
    }

    /// Review #466 F6: a symbolic link at the pin root, and a kernel without
    /// its BTF, refuse before the load and record nothing — unless the
    /// degraded-mode opt-in.
    #[test]
    fn the_deny_hooks_prerequisites_refuse_before_the_load() {
        let mut boot = BootSequence::new();
        let why = Some("the bpffs pin root /sys/fs/bpf/northnarrow is a symbolic link".to_string());
        assert!(matches!(
            pin_root_decided(&mut boot, why.clone(), false).unwrap(),
            Verdict::Refused(w) if w.contains("symbolic link")
        ));
        assert!(!has(&boot, BootStep::PinRoot));
        assert_eq!(
            pin_root_decided(&mut boot, why, true).unwrap(),
            Verdict::Passed
        );
        assert!(has(&boot, BootStep::PinRoot));
        let mut boot = BootSequence::new();
        assert_eq!(
            pin_root_decided(&mut boot, None, false).unwrap(),
            Verdict::Passed
        );
        assert!(has(&boot, BootStep::PinRoot));

        let dir = tempfile::tempdir().unwrap();
        let btf = dir.path().join("sys/kernel/btf");
        let mut boot = BootSequence::new();
        for setup in ["absent", "empty"] {
            if setup == "empty" {
                std::fs::create_dir_all(&btf).unwrap();
                std::fs::write(btf.join("vmlinux"), b"").unwrap();
            }
            assert!(
                matches!(
                    vmlinux_btf_in(&mut boot, dir.path(), false).unwrap(),
                    Verdict::Refused(w) if w.contains("vmlinux BTF unavailable")
                ),
                "{setup}"
            );
            assert!(!has(&boot, BootStep::VmlinuxBtf), "{setup}");
        }
        assert_eq!(
            vmlinux_btf_in(&mut boot, dir.path(), true).unwrap(),
            Verdict::Passed
        );
        let mut boot = BootSequence::new();
        std::fs::write(btf.join("vmlinux"), b"\x9f\xeb\x01\x00").unwrap();
        assert_eq!(
            vmlinux_btf_in(&mut boot, dir.path(), false).unwrap(),
            Verdict::Passed
        );
        assert!(has(&boot, BootStep::VmlinuxBtf));
    }

    /// The agent's own mount table as the lab guest shows it under the
    /// unit: `/` and the unit's `ReadWritePaths=` binds, each directory
    /// onto itself.
    const SANDBOX: &str = "\
29 1 252:1 / / ro,relatime shared:1 - ext4 /dev/vda1 rw,discard
701 29 252:1 /etc/northnarrow /etc/northnarrow rw,relatime shared:1 - ext4 /dev/vda1 rw
702 29 252:1 /var/lib/northnarrow /var/lib/northnarrow rw,relatime shared:1 - ext4 /dev/vda1 rw
";

    fn agent_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/northnarrow"),
            PathBuf::from("/var/lib/northnarrow"),
        ]
    }

    const PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

    /// [`agent_mounts_decided`] on `table` with no previous agent.
    fn mounts(boot: &mut BootSequence, table: Result<Vec<u8>, String>) -> Verdict {
        agent_mounts_decided(
            boot,
            table,
            &agent_dirs(),
            Path::new(PIN_ROOT),
            &continuity::PreviousAgent::None,
            &[],
        )
        .unwrap()
    }

    /// [`signing_identity_decided`] with no previous agent.
    fn identity(boot: &mut BootSequence, paths: &continuity::IdentityPaths) -> Verdict {
        signing_identity_decided(
            boot,
            paths,
            &continuity::PreviousAgent::None,
            Path::new("/proc/self/exe"),
        )
        .unwrap()
    }

    fn identity_paths(dir: &Path) -> continuity::IdentityPaths {
        continuity::IdentityPaths {
            signing_key: dir.join("agent.sig.key"),
            agent_id: dir.join("agent_id"),
            heads: dir.join("chain_heads.json"),
            chains: vec![dir.join("audit.log")],
        }
    }

    /// A previous agent whose `PROTECTED_INODES` holds the inodes of
    /// `paths` (each as [`continuity::inode_key`] reads it; the binaries
    /// followed, as the attach stats them).
    fn pinned(dirs: &[&Path], binaries: &[&Path]) -> continuity::PreviousAgent {
        use std::os::unix::fs::MetadataExt;
        let mut keys: Vec<common::wire::InodeKey> = dirs
            .iter()
            .map(|d| continuity::inode_key(d).unwrap())
            .collect();
        for b in binaries {
            let m = std::fs::metadata(b).unwrap();
            keys.push(common::wire::InodeKey {
                dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
                ino: m.ino(),
            });
        }
        continuity::PreviousAgent::Pinned(Box::new(move |k| {
            keys.iter().any(|x| x.dev == k.dev && x.ino == k.ino)
        }))
    }

    /// Lab PR 265 (review #466 F4-bis): the unit's binds and a separate
    /// `/var` pass and record the step; an empty directory bound over the
    /// configuration directory, a tmpfs over the state directory, a table
    /// that cannot be read or names no root refuse and record nothing.
    #[test]
    fn a_mount_over_the_agents_directories_refuses_and_records_nothing() {
        let mut boot = BootSequence::new();
        assert_eq!(mounts(&mut boot, Ok(SANDBOX.into())), Verdict::Passed);
        assert!(has(&boot, BootStep::AgentMounts));
        let var = "\
29 1 252:1 / / rw - ext4 /dev/vda1 rw
40 29 252:2 / /var rw - ext4 /dev/vda2 rw
702 40 252:2 /lib/northnarrow /var/lib/northnarrow rw - ext4 /dev/vda2 rw
";
        let mut boot = BootSequence::new();
        assert_eq!(
            mounts(&mut boot, Ok(var.into())),
            Verdict::Passed,
            "a separate /var is a normal layout"
        );
        let hidden = [
            format!("{SANDBOX}800 701 252:1 /root/empty /etc/northnarrow rw - ext4 /dev/vda1 rw\n"),
            format!("{SANDBOX}801 702 0:90 / /var/lib/northnarrow rw - tmpfs tmpfs rw\n"),
        ];
        for table in hidden {
            let mut boot = BootSequence::new();
            let v = mounts(&mut boot, Ok(table.into_bytes()));
            assert!(
                matches!(&v, Verdict::Refused(w) if w.contains("a mount hides the agent's own files")),
                "{v:?}"
            );
            assert!(!has(&boot, BootStep::AgentMounts));
        }
        for table in [Err("No such file or directory".to_string()), Ok(Vec::new())] {
            let mut boot = BootSequence::new();
            let v = mounts(&mut boot, table);
            assert!(
                matches!(&v, Verdict::Refused(w) if w.contains("cannot be checked")),
                "{v:?}"
            );
            assert!(!has(&boot, BootStep::AgentMounts));
        }
    }

    /// Review of #468 R2: one bpffs alone at `/sys/fs/bpf`, nothing over the
    /// pin root — a second bpffs or a tmpfs stacked there, or a mount over
    /// the pin root, hides the previous agent's pins and refuses; no bpffs
    /// at all has nothing to hide.
    #[test]
    fn the_bpffs_of_the_pins_is_the_one_alone_at_sys_fs_bpf() {
        let bpffs = format!("{SANDBOX}554 29 0:30 / /sys/fs/bpf rw - bpf bpf rw,mode=700\n");
        let mut boot = BootSequence::new();
        assert_eq!(
            mounts(&mut boot, Ok(bpffs.clone().into_bytes())),
            Verdict::Passed
        );
        assert_eq!(
            mounts(&mut BootSequence::new(), Ok(SANDBOX.into())),
            Verdict::Passed,
            "no bpffs"
        );
        for (what, extra) in [
            (
                "stacked bpffs",
                "555 554 0:91 / /sys/fs/bpf rw - bpf bpf rw\n",
            ),
            (
                "stacked tmpfs",
                "555 554 0:92 / /sys/fs/bpf rw - tmpfs tmpfs rw\n",
            ),
            (
                "over the pin root",
                "556 554 0:93 / /sys/fs/bpf/northnarrow rw - bpf bpf rw\n",
            ),
        ] {
            let mut boot = BootSequence::new();
            let v = mounts(&mut boot, Ok(format!("{bpffs}{extra}").into_bytes()));
            assert!(
                matches!(&v, Verdict::Refused(w) if w.contains("hides the pins")),
                "{what}: {v:?}"
            );
            assert!(!has(&boot, BootStep::AgentMounts), "{what}");
        }
        let tmpfs = format!("{SANDBOX}554 29 0:30 / /sys/fs/bpf rw - tmpfs tmpfs rw\n");
        assert!(matches!(
            mounts(&mut BootSequence::new(), Ok(tmpfs.into_bytes())),
            Verdict::Refused(w) if w.contains("not a bpffs")
        ));
    }

    /// Review of #468 R1/R3: a line not in the kernel's shape refuses only
    /// when it may be a mount over the agent's directories (or over the pin
    /// root); one elsewhere never refuses.
    #[test]
    fn a_malformed_line_refuses_only_when_it_may_concern_the_agents_directories() {
        for (line, refused) in [
            ("900 29 252:1 / /home/x rw - ext4\n", false),
            ("900 29 252:1 / /etc/northnarrow rw - ext4\n", true),
            (
                "900 29 252:1 / /var/lib/northnarrow/detections rw ext4 /dev/x rw\n",
                true,
            ),
            ("900 29\n", true),
            ("900 29 252:1 / /sys/fs/bpf rw - bpf\n", true),
        ] {
            let v = mounts(
                &mut BootSequence::new(),
                Ok(format!("{SANDBOX}{line}").into_bytes()),
            );
            assert_eq!(matches!(v, Verdict::Refused(_)), refused, "{line:?}: {v:?}");
        }
    }

    /// Review of #468 R2, fix a, the view: with the previous agent's pins,
    /// the agent's directories that exist must be the inodes it protected —
    /// another directory at the name (a copy bound over an ancestor, a
    /// rename above it) refuses; an absent one is not compared; no pins:
    /// nothing to compare; pins whose inode map cannot be read refuse.
    #[test]
    fn the_agents_directories_are_the_inodes_the_previous_agent_protected() {
        let d = tempfile::tempdir().unwrap();
        let (config, state, copy) = (
            d.path().join("etc"),
            d.path().join("var"),
            d.path().join("copy"),
        );
        for p in [&config, &state, &copy] {
            std::fs::create_dir(p).unwrap();
        }
        let previous = pinned(&[&config, &state], &[]);
        let decided = |previous: &continuity::PreviousAgent, own: &[PathBuf]| {
            let mut boot = BootSequence::new();
            let v = agent_mounts_decided(
                &mut boot,
                Ok(SANDBOX.into()),
                &agent_dirs(),
                Path::new(PIN_ROOT),
                previous,
                own,
            )
            .unwrap();
            assert_eq!(v == Verdict::Passed, has(&boot, BootStep::AgentMounts));
            v
        };
        assert_eq!(
            decided(&previous, &[config.clone(), state.clone()]),
            Verdict::Passed
        );
        assert!(matches!(
            decided(&previous, &[config.clone(), copy.clone()]),
            Verdict::Refused(w) if w.contains("is not the directory the previous agent protected")
        ));
        // the copy in place of the real one (what a rename above it shows)
        std::fs::rename(&config, d.path().join("etc.real")).unwrap();
        std::fs::rename(&copy, &config).unwrap();
        assert!(matches!(
            decided(&previous, &[config.clone(), state.clone()]),
            Verdict::Refused(_)
        ));
        assert_eq!(
            decided(&previous, &[d.path().join("absent"), state.clone()]),
            Verdict::Passed,
            "an absent directory is not compared"
        );
        assert_eq!(
            decided(
                &continuity::PreviousAgent::None,
                std::slice::from_ref(&config)
            ),
            Verdict::Passed,
            "no pins"
        );
        assert!(matches!(
            decided(&continuity::PreviousAgent::Unreadable("EPERM".into()), std::slice::from_ref(&state)),
            Verdict::Refused(w) if w.contains("cannot be read")
        ));
    }

    /// Review of #468 R2, fix a, the restart: a start that runs the binary
    /// the previous agent protected is its restart — its key must be in a
    /// directory that agent protected and there, never minted (the
    /// reviewer's V3b: `ExecStart=` redefined with the key in an empty
    /// directory). A start of another binary (the tests' copies) is judged
    /// by the evidence alone.
    #[test]
    fn a_restart_of_the_protected_binary_never_mints() {
        let d = tempfile::tempdir().unwrap();
        let (installed, copy) = (d.path().join("northnarrow-agent"), d.path().join("e2etest"));
        std::fs::write(&installed, "ELF").unwrap();
        std::fs::write(&copy, "ELF").unwrap();
        let etc = d.path().join("etc");
        let empty = d.path().join("empty");
        std::fs::create_dir(&etc).unwrap();
        std::fs::create_dir(&empty).unwrap();
        let key = etc.join("agent.sig.key");
        crate::keys::AgentSigningKey::load_or_bootstrap(&key).unwrap();
        let previous = pinned(&[&etc], &[&installed]);
        let decided = |paths: &continuity::IdentityPaths, exe: &Path| {
            let mut boot = BootSequence::new();
            let v = signing_identity_decided(&mut boot, paths, &previous, exe).unwrap();
            assert_eq!(v == Verdict::Passed, has(&boot, BootStep::SigningIdentity));
            v
        };
        assert_eq!(
            decided(&identity_paths(&etc), &installed),
            Verdict::Passed,
            "a restart"
        );
        // V3b: the installed binary, its key, id and chains in an empty
        // directory: nothing there says an identity, but it is a restart
        let v = decided(&identity_paths(&empty), &installed);
        assert!(
            matches!(&v, Verdict::Refused(w) if w.contains("not in a directory that agent protected")
                && w.contains("never mints")),
            "{v:?}"
        );
        assert!(!empty.join("agent.sig.key").exists(), "a key minted");
        // the key gone from the protected directory, its public half too
        std::fs::remove_file(&key).unwrap();
        std::fs::remove_file(etc.join("agent.sig.pub")).unwrap();
        assert!(matches!(
            decided(&identity_paths(&etc), &installed),
            Verdict::Refused(w) if w.contains("a restart never mints a key")
        ));
        // another binary (a test's copy) in an empty directory: a first start
        assert_eq!(decided(&identity_paths(&empty), &copy), Verdict::Passed);
        // no pins (a boot, or removed on purpose): the evidence alone
        let mut boot = BootSequence::new();
        assert_eq!(
            signing_identity_decided(
                &mut boot,
                &identity_paths(&empty),
                &continuity::PreviousAgent::None,
                &installed
            )
            .unwrap(),
            Verdict::Passed
        );
        assert!(matches!(
            signing_identity_decided(
                &mut BootSequence::new(),
                &identity_paths(&empty),
                &continuity::PreviousAgent::Unreadable("EPERM".into()),
                &installed
            )
            .unwrap(),
            Verdict::Refused(w) if w.contains("cannot be read")
        ));
    }

    /// Lab PR 265: the environment variable that makes
    /// [`mounts_in_a_namespace_of_its_own`] run (inside `unshare -rm`, in
    /// the directory it names); without it the test does nothing.
    const MOUNT_NS_ENV: &str = "NN_TEST_K265_MOUNT_NS_DIR";

    /// Lab PR 265 (review #466's nit on the fallback's mount check): the
    /// check on the real table, `/proc/self/mountinfo`, with real mounts —
    /// in a user and mount namespace of its own (`unshare -rm`), where an
    /// unprivileged test may mount. Where the host allows no unprivileged
    /// user namespace (AppArmor's restriction of them) it says so and
    /// passes.
    #[test]
    fn the_real_mount_table_in_a_namespace_of_its_own() {
        let probe = std::process::Command::new("unshare")
            .args(["-rm", "true"])
            .stdin(std::process::Stdio::null())
            .output();
        if !probe.as_ref().is_ok_and(|o| o.status.success()) {
            eprintln!("no unprivileged user and mount namespace here (unshare -rm): {probe:?}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let out = std::process::Command::new("unshare")
            .arg("-rm")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "boot::checks::tests::mounts_in_a_namespace_of_its_own",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MOUNT_NS_ENV, dir.path())
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "the helper did not run: {text}");
        assert!(text.contains("k265 mount namespace: 6 cases"), "{text}");
    }

    /// The other half of [`the_real_mount_table_in_a_namespace_of_its_own`]:
    /// inside the namespace, a directory bound onto itself passes; an empty
    /// directory bound over it, a tmpfs over it, a file bound over a file in
    /// it are refused, each from `/proc/self/mountinfo`. A no-op without
    /// [`MOUNT_NS_ENV`].
    #[test]
    #[ignore = "run by the_real_mount_table_in_a_namespace_of_its_own, under unshare -rm"]
    fn mounts_in_a_namespace_of_its_own() {
        let Some(root) = std::env::var_os(MOUNT_NS_ENV) else {
            return;
        };
        let root = PathBuf::from(root);
        let state = root.join("state");
        let empty = root.join("empty");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(state.join("agent.sig.key"), "k\n").unwrap();
        std::fs::write(root.join("other.key"), "o\n").unwrap();
        let mount = |args: &[&std::ffi::OsStr]| {
            let st = std::process::Command::new("mount")
                .args(args)
                .status()
                .unwrap();
            assert!(st.success(), "mount {args:?}");
        };
        let umount = |p: &Path| {
            let st = std::process::Command::new("umount")
                .arg(p)
                .status()
                .unwrap();
            assert!(st.success(), "umount {}", p.display());
        };
        let check = || {
            let mut boot = BootSequence::new();
            let table = std::fs::read(continuity::OWN_MOUNTINFO).map_err(|e| e.to_string());
            let v = agent_mounts_decided(
                &mut boot,
                table,
                &continuity::spelled(&[&state]),
                Path::new(PIN_ROOT),
                &continuity::PreviousAgent::None,
                &[],
            )
            .unwrap();
            assert_eq!(v == Verdict::Passed, has(&boot, BootStep::AgentMounts));
            v
        };
        assert_eq!(check(), Verdict::Passed, "nothing mounted");
        mount(&["--bind".as_ref(), state.as_os_str(), state.as_os_str()]);
        assert_eq!(check(), Verdict::Passed, "a bind onto itself");
        mount(&["--bind".as_ref(), empty.as_os_str(), state.as_os_str()]);
        let v = check();
        assert!(
            matches!(&v, Verdict::Refused(w) if w.contains("another directory or file bound there")),
            "{v:?}"
        );
        umount(&state);
        mount(&[
            "-t".as_ref(),
            "tmpfs".as_ref(),
            "k265".as_ref(),
            state.as_os_str(),
        ]);
        let v = check();
        assert!(
            matches!(&v, Verdict::Refused(w) if w.contains("another filesystem mounted there")),
            "{v:?}"
        );
        umount(&state);
        let key = state.join("agent.sig.key");
        mount(&[
            "--bind".as_ref(),
            root.join("other.key").as_os_str(),
            key.as_os_str(),
        ]);
        let v = check();
        assert!(
            matches!(&v, Verdict::Refused(w) if w.contains("agent.sig.key (")),
            "{v:?}"
        );
        umount(&key);
        // review of #468, case A: a directory whose name holds U+00A0 bound
        // over the state directory, the unit's bind of it on top — the
        // split on Unicode spaces made both lines look elsewhere
        use std::os::unix::ffi::OsStrExt;
        let fake = root
            .join(std::ffi::OsStr::from_bytes(b"fake\xc2\xa0"))
            .join("x");
        std::fs::create_dir_all(&fake).unwrap();
        mount(&["--bind".as_ref(), fake.as_os_str(), state.as_os_str()]);
        mount(&["--bind".as_ref(), state.as_os_str(), state.as_os_str()]);
        let v = check();
        assert!(
            matches!(&v, Verdict::Refused(w) if w.contains("another directory or file bound there")),
            "{v:?}"
        );
        umount(&state);
        umount(&state);
        // case B: a tmpfs on a name that is not UTF-8, elsewhere — the
        // table read as text could not be read at all
        let other = root.join(std::ffi::OsStr::from_bytes(b"other\xff"));
        std::fs::create_dir_all(&other).unwrap();
        mount(&[
            "-t".as_ref(),
            "tmpfs".as_ref(),
            "k265".as_ref(),
            other.as_os_str(),
        ]);
        assert_eq!(check(), Verdict::Passed, "a mount elsewhere, not UTF-8");
        println!("k265 mount namespace: 6 cases");
    }

    /// Lab PR 265 (review #466 F4-bis): a fresh directory passes (a first
    /// install mints its key); the key there passes, whatever else is;
    /// an absent key where its public half, the install's id or a signed
    /// row of a chain is found refuses, records nothing and mints nothing.
    #[test]
    fn a_key_absent_where_an_identity_was_refuses_and_mints_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = identity_paths(dir.path());
        let mut boot = BootSequence::new();
        assert_eq!(identity(&mut boot, &paths), Verdict::Passed);
        assert!(has(&boot, BootStep::SigningIdentity));
        // a first boot: the key, its public half, the id, a signed row
        let key = crate::keys::AgentSigningKey::load_or_bootstrap(&paths.signing_key).unwrap();
        let id = crate::agent_id::load_or_bootstrap(&paths.agent_id).unwrap();
        let mut log = crate::audit::AuditLog::open(&dir.path().join("audit.log"), key, id).unwrap();
        log.boot_probe(
            None,
            "no-manifest",
            "none",
            &crate::audit::AgentBuild {
                version: "0.0.0",
                features: Vec::new(),
                bpf_guard_enforce: true,
            },
        )
        .unwrap();
        drop(log);
        let mut boot = BootSequence::new();
        assert_eq!(identity(&mut boot, &paths), Verdict::Passed);
        // the key removed: each piece of evidence alone refuses
        let secret = std::fs::read(&paths.signing_key).unwrap();
        std::fs::remove_file(&paths.signing_key).unwrap();
        let public = crate::keys::verifying_key_path(&paths.signing_key);
        let saved = |p: &Path| (p.to_path_buf(), std::fs::read(p).unwrap());
        let evidence = [
            saved(&public),
            saved(&paths.agent_id),
            saved(&dir.path().join("audit.log")),
        ];
        for (p, _) in &evidence {
            std::fs::rename(p, p.with_extension("aside")).unwrap();
        }
        for (p, bytes) in &evidence {
            std::fs::write(p, bytes).unwrap();
            let mut boot = BootSequence::new();
            let v = identity(&mut boot, &paths);
            assert!(
                matches!(&v, Verdict::Refused(w) if w.contains("none is minted")),
                "{}: {v:?}",
                p.display()
            );
            assert!(!has(&boot, BootStep::SigningIdentity));
            assert!(!paths.signing_key.exists(), "a key minted");
            assert_eq!(&std::fs::read(p).unwrap(), bytes, "{}", p.display());
            std::fs::remove_file(p).unwrap();
        }
        // nothing left: a fresh install again
        let mut boot = BootSequence::new();
        assert_eq!(identity(&mut boot, &paths), Verdict::Passed);
        // the key back: passes
        std::fs::write(&paths.signing_key, &secret).unwrap();
        for (p, bytes) in &evidence {
            std::fs::write(p, bytes).unwrap();
        }
        let mut boot = BootSequence::new();
        assert_eq!(identity(&mut boot, &paths), Verdict::Passed);
    }

    /// The proof is given once every check passed, and the attach phase
    /// begins with it: what no other path reaches.
    #[test]
    fn every_check_passed_gives_the_proof() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sys/kernel/security")).unwrap();
        std::fs::write(dir.path().join(lsm::ACTIVE_LSM_REL), "capability,bpf\n").unwrap();
        let mut boot = BootSequence::new();
        assert_eq!(mounts(&mut boot, Ok(SANDBOX.into())), Verdict::Passed);
        assert_eq!(
            identity(&mut boot, &identity_paths(dir.path())),
            Verdict::Passed
        );
        // the eBPF object and the BTF are the host's: decided here as they
        // pass on a host that has them
        boot.passed(BootStep::EbpfObject).unwrap();
        assert_eq!(
            state_dir_in(&mut boot, dir.path()).unwrap(),
            Verdict::Passed
        );
        btf_offsets_decided(
            &mut boot,
            &ResolveOutcome::SkippedNoBtf {
                reason: "test".into(),
            },
        )
        .unwrap();
        let all = CapsReading::Read {
            effective: u64::MAX,
            note: None,
        };
        assert!(matches!(
            capabilities_decided(&mut boot, &all, false).unwrap(),
            BootGate::Start { degraded } if degraded.is_empty()
        ));
        let c = install_manifest_for(
            &mut boot,
            &dir.path().join("install-manifest.json"),
            Path::new("/proc/self/exe"),
            &dir.path().join("audit.log"),
            None,
        )
        .unwrap();
        assert!(!c.fatal);
        let key = dir.path().join("agent.sig.key");
        let audit = audit_log_with(
            &mut boot,
            &dir.path().join("audit.log"),
            &key,
            [1; 16],
            false,
            None,
        )
        .unwrap();
        assert!(!audit.fatal);
        assert!(matches!(audit.open, AuditOpen::Open(_)));
        assert!(matches!(
            bpf_lsm_in(&mut boot, dir.path(), false).unwrap().1,
            LsmGate::Proceed
        ));
        assert_eq!(
            pin_root_decided(&mut boot, None, false).unwrap(),
            Verdict::Passed
        );
        std::fs::create_dir_all(dir.path().join("sys/kernel/btf")).unwrap();
        std::fs::write(dir.path().join("sys/kernel/btf/vmlinux"), b"BTF").unwrap();
        assert_eq!(
            vmlinux_btf_in(&mut boot, dir.path(), false).unwrap(),
            Verdict::Passed
        );
        let _proof = boot.verify_integrity().expect("every check passed");
        assert_eq!(boot.phase(), BootPhase::Attach);
    }
}
