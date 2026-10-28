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

use std::path::Path;

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

/// The state directory `dir`, and the agent's own entries in it, are not
/// symbolic links ([`crate::anti_tamper::filesystem::refuse_linked_state_dir`]).
pub fn state_dir(boot: &mut BootSequence, dir: &Path) -> Result<Verdict, BootOrderError> {
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
/// passes (its degradations are the caller's to sign).
pub fn capabilities(
    boot: &mut BootSequence,
    detect_only: bool,
) -> Result<(CapsReading, BootGate), BootOrderError> {
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
/// ([`install_manifest::check`]; `own_exe`: the running agent): every
/// outcome passes but a fatal one — a mismatch, an unreadable manifest, or
/// a missing one after a verified boot of this install (DEP-009, the
/// signed chain at `audit_log` the sentinel) — unless `allow_unverified`
/// ([`install_manifest::ALLOW_UNVERIFIED_ENV`]) is `1`.
pub fn install_manifest(
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
            match crate::audit::verified_boot_recorded(audit_log) {
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
    /// The start is refused: the log cannot be written and
    /// `NN_AUDIT_ALLOW_UNWRITABLE=1` is not set.
    pub fatal: bool,
}

/// The audit log at `path` can be written: opened for append without
/// writing, or its directory able to take it
/// ([`audit_preflight::preflight_writable`];
/// `closed_by_previous_hooks`: the early registration in the pinned
/// `PROTECTED_PIDS` failed, so a permission error is left to the boot's
/// write probe). An unwritable log refuses the start unless
/// `allow_unwritable` ([`crate::audit::AUDIT_ALLOW_UNWRITABLE_ENV`]) is `1`.
pub fn audit_log(
    boot: &mut BootSequence,
    path: &Path,
    closed_by_previous_hooks: bool,
    allow_unwritable: Option<&str>,
) -> Result<AuditCheck, BootOrderError> {
    let preflight = audit_preflight::preflight_writable(path, closed_by_previous_hooks);
    let fatal = matches!(preflight, AuditPreflight::Unwritable(_))
        && crate::audit::audit_failure_is_fatal(allow_unwritable);
    if !fatal {
        boot.passed(BootStep::AuditWritable)?;
    }
    Ok(AuditCheck { preflight, fatal })
}

/// `bpf` in the LSMs the kernel runs (`sys/kernel/security/lsm` under
/// `root`, `/` on a host; [`lsm::gate`]): every outcome but
/// [`LsmGate::Refuse`] passes — the degraded-mode opt-in (`allow_degraded`)
/// and an unreadable list go on, signed by the caller.
pub fn bpf_lsm(
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
            state_dir(&mut boot, &link).unwrap(),
            Verdict::Refused(why) if why.contains("symbolic link")
        ));
        assert!(!has(&boot, BootStep::StateDir));
        assert_eq!(state_dir(&mut boot, &real).unwrap(), Verdict::Passed);
        assert!(has(&boot, BootStep::StateDir));
        // a missing directory is fine (the attach creates it)
        let mut boot = BootSequence::new();
        assert_eq!(
            state_dir(&mut boot, &dir.path().join("absent")).unwrap(),
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
        let c = install_manifest(
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
        let c = install_manifest(
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
        let not_a_file = dir.path().join("audit.log");
        std::fs::create_dir(&not_a_file).unwrap();
        let mut boot = BootSequence::new();
        let c = audit_log(&mut boot, &not_a_file, false, None).unwrap();
        assert!(matches!(c.preflight, AuditPreflight::Unwritable(_)));
        assert!(c.fatal);
        assert!(!has(&boot, BootStep::AuditWritable));
        let c = audit_log(&mut boot, &not_a_file, false, Some("1")).unwrap();
        assert!(!c.fatal);
        assert!(has(&boot, BootStep::AuditWritable));
        let mut boot = BootSequence::new();
        let c = audit_log(&mut boot, &dir.path().join("fresh.log"), false, None).unwrap();
        assert_eq!(c.preflight, AuditPreflight::Writable);
        assert!(has(&boot, BootStep::AuditWritable));
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
        let (state, gate) = bpf_lsm(&mut boot, dir.path(), false).unwrap();
        assert!(matches!(state, BpfLsm::Absent { .. }));
        assert!(matches!(gate, LsmGate::Refuse { .. }));
        assert!(!has(&boot, BootStep::BpfLsm));
        let (_, gate) = bpf_lsm(&mut boot, dir.path(), true).unwrap();
        assert!(matches!(gate, LsmGate::Degraded { .. }));
        assert!(has(&boot, BootStep::BpfLsm));
    }

    /// The proof is given once every check passed, and the attach phase
    /// begins with it: what no other path reaches.
    #[test]
    fn every_check_passed_gives_the_proof() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sys/kernel/security")).unwrap();
        std::fs::write(dir.path().join(lsm::ACTIVE_LSM_REL), "capability,bpf\n").unwrap();
        let mut boot = BootSequence::new();
        // the eBPF object and the BTF are the host's: decided here as they
        // pass on a host that has them
        boot.passed(BootStep::EbpfObject).unwrap();
        assert_eq!(state_dir(&mut boot, dir.path()).unwrap(), Verdict::Passed);
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
        let c = install_manifest(
            &mut boot,
            &dir.path().join("install-manifest.json"),
            Path::new("/proc/self/exe"),
            &dir.path().join("audit.log"),
            None,
        )
        .unwrap();
        assert!(!c.fatal);
        assert!(
            !audit_log(&mut boot, &dir.path().join("audit.log"), false, None)
                .unwrap()
                .fatal
        );
        assert!(matches!(
            bpf_lsm(&mut boot, dir.path(), false).unwrap().1,
            LsmGate::Proceed
        ));
        let _proof = boot.verify_integrity().expect("every check passed");
        assert_eq!(boot.phase(), BootPhase::Attach);
    }
}
