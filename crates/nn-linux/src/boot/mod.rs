//! The boot sequence's typed phases and the proof that every preflight
//! check ran (lab PR 218): the permit the eBPF loader and the deny hooks'
//! attach take, the degradations of a run, and the sensors' attach points
//! the boot's capability manifest lists — what the sensors take and report
//! (Wave 4 restructure, R09b, lab PR 254: cut verbatim from the agent's
//! `boot`, which re-exports them; its deny self-test, BPF LSM gate, trust
//! level and signed manifest stay in the agent).
//!
//! Wave 4 restructure, R11b (lab PR 262): the permit is
//! [`IntegrityVerified`], and it proves the checks, not only their order.
//! The steps the attach depends on ([`BootStep::is_checked`]) are recorded
//! by [`checks`] alone, each once its check ran against the host and
//! passed — [`BootSequence::done`] refuses them —, and
//! [`BootSequence::verify_integrity`], the one way to an
//! [`IntegrityVerified`], requires every one of them. The eBPF object's
//! load (with the maps it pins), every pin and every attach take the proof:
//! nothing reaches the kernel before every integrity check has passed. The
//! BPF LSM gate moved here from the agent (`lsm`) so that its check records
//! its step too.

pub mod checks;
pub mod degradation;
pub mod lsm;
pub mod manifest;

use tracing::info;

/// The phases of a start, in their order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BootPhase {
    /// Checks only: nothing loaded into or attached to the kernel.
    Preflight,
    /// The eBPF object loads; the sensors and the deny hooks attach.
    Attach,
    /// One deny hook exercised against the agent itself.
    SelfTest,
    /// The signed audit log: `agent_boot`, then the degradations so far.
    Attest,
    /// The subsystems that need the audit log.
    Subsystems,
    /// The capability manifest and the trust level signed; the event loop.
    Run,
}

impl BootPhase {
    /// Every phase, in order.
    pub const ORDER: [BootPhase; 6] = [
        BootPhase::Preflight,
        BootPhase::Attach,
        BootPhase::SelfTest,
        BootPhase::Attest,
        BootPhase::Subsystems,
        BootPhase::Run,
    ];

    pub fn name(self) -> &'static str {
        match self {
            BootPhase::Preflight => "preflight",
            BootPhase::Attach => "attach",
            BootPhase::SelfTest => "self-test",
            BootPhase::Attest => "attest",
            BootPhase::Subsystems => "subsystems",
            BootPhase::Run => "run",
        }
    }

    /// The phase after this one (`None` after [`BootPhase::Run`]).
    pub fn next(self) -> Option<BootPhase> {
        let i = Self::ORDER.iter().position(|p| *p == self)?;
        Self::ORDER.get(i + 1).copied()
    }

    /// What this phase must have done before the next one starts.
    pub fn required(self) -> &'static [BootStep] {
        use BootStep::*;
        match self {
            BootPhase::Preflight => &[
                EbpfObject,
                StateDir,
                BtfOffsets,
                Capabilities,
                InstallManifest,
                AuditWritable,
                BpfLsm,
            ],
            BootPhase::Attach => &[Sensors, AntiTamper],
            BootPhase::SelfTest => &[DenySelfTest],
            BootPhase::Attest => &[AgentBoot, BootDegradations],
            BootPhase::Subsystems => &[],
            BootPhase::Run => &[CapabilityManifest],
        }
    }
}

/// One step of a start, each in one phase ([`BootStep::phase`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BootStep {
    /// The embedded eBPF object is real and intact.
    EbpfObject,
    /// The state directory is not a symbolic link.
    StateDir,
    /// The kernel offsets the programs read, resolved from the BTF.
    BtfOffsets,
    /// The chains against their anchored heads.
    ChainHeads,
    /// The agent's identity.
    Identity,
    /// The capability bounding set (`caps::boot_gate`).
    Capabilities,
    /// The running binaries against the install manifest.
    InstallManifest,
    /// The audit log can be written: opened for append without writing,
    /// and (R11b, lab PR 262) its chain opened — the tail read, a torn last
    /// write repaired — before anything is loaded.
    AuditWritable,
    /// The host hardening table.
    HostHardening,
    /// `bpf` in the active LSMs, or the degraded-mode opt-in (the agent's
    /// `boot::lsm`).
    BpfLsm,
    /// The eBPF object loaded and the sensors attached.
    Sensors,
    /// The deny hooks attached and the agent registered.
    AntiTamper,
    /// The deny self-test ran (the agent's `boot::deny_selftest`).
    DenySelfTest,
    /// The signed `agent_boot` entry is written.
    AgentBoot,
    /// The degradations found before the audit log opened are signed.
    BootDegradations,
    /// The capability manifest is signed.
    CapabilityManifest,
}

impl BootStep {
    /// Wave 4 restructure, R11b (lab PR 262): a step only its check records
    /// ([`checks`]), never [`BootSequence::done`] — the ones the attach
    /// depends on: the eBPF object, the state directory, the BTF offsets,
    /// the capabilities, the install manifest, the audit log, the BPF LSM.
    pub fn is_checked(self) -> bool {
        use BootStep::*;
        matches!(
            self,
            EbpfObject
                | StateDir
                | BtfOffsets
                | Capabilities
                | InstallManifest
                | AuditWritable
                | BpfLsm
        )
    }

    pub fn phase(self) -> BootPhase {
        use BootStep::*;
        match self {
            EbpfObject | StateDir | BtfOffsets | ChainHeads | Identity | Capabilities
            | InstallManifest | AuditWritable | HostHardening | BpfLsm => BootPhase::Preflight,
            Sensors | AntiTamper => BootPhase::Attach,
            DenySelfTest => BootPhase::SelfTest,
            AgentBoot | BootDegradations => BootPhase::Attest,
            CapabilityManifest => BootPhase::Run,
        }
    }

    pub fn name(self) -> &'static str {
        use BootStep::*;
        match self {
            EbpfObject => "ebpf_object",
            StateDir => "state_dir",
            BtfOffsets => "btf_offsets",
            ChainHeads => "chain_heads",
            Identity => "identity",
            Capabilities => "capabilities",
            InstallManifest => "install_manifest",
            AuditWritable => "audit_writable",
            HostHardening => "host_hardening",
            BpfLsm => "bpf_lsm",
            Sensors => "sensors",
            AntiTamper => "anti_tamper",
            DenySelfTest => "deny_self_test",
            AgentBoot => "agent_boot",
            BootDegradations => "boot_degradations",
            CapabilityManifest => "capability_manifest",
        }
    }
}

/// A start that does not follow the phases.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BootOrderError {
    #[error("boot step {step} belongs to the {belongs} phase, the start is in {current}")]
    WrongPhase {
        step: &'static str,
        belongs: &'static str,
        current: &'static str,
    },
    #[error("boot phase {to} cannot follow {from}")]
    OutOfOrder {
        from: &'static str,
        to: &'static str,
    },
    #[error("boot phase {phase} left without: {missing}")]
    Incomplete {
        phase: &'static str,
        missing: String,
    },
    /// R11b (lab PR 262): [`BootSequence::done`] of a step only its check
    /// records ([`BootStep::is_checked`]).
    #[error("boot step {step} is recorded by its check only (boot::checks)")]
    Unchecked { step: &'static str },
}

/// The proof that every integrity check of the start passed: the only way
/// into the kernel (lab PR 218's `AttachPermit`; Wave 4 restructure, R11b,
/// lab PR 262).
///
/// The eBPF object's load — and the by-name pins of its maps it makes —
/// takes it ([`crate::sensors::SensorMultiplexer::start`],
/// [`crate::sensors::SensorMultiplexer::start_with_net`],
/// [`crate::sensors::exec::ExecSensor::start`]), and so do the pins and the
/// attaches that follow ([`crate::sensors::SensorMultiplexer::attach_anti_tamper`],
/// [`crate::anti_tamper::attach`],
/// [`crate::sensors::SensorMultiplexer::attach_exploit_guard`]); every later
/// attach goes through the multiplexer's object, which only a proof loads.
/// The object's bytes are this crate's (`sensors::ebpf_object`): only its
/// loaders load them.
///
/// No public field, not `Clone`, `Copy` nor `Default`: outside tests its
/// one constructor is [`BootSequence::verify_integrity`], which gives one
/// only once every preflight step is recorded — and the steps the attach
/// depends on are recorded by their checks alone ([`checks`]).
///
/// ```compile_fail,E0451
/// // Not built outside this crate: its field is private.
/// let forged = nn_linux::boot::IntegrityVerified { _sealed: () };
/// ```
///
/// ```compile_fail,E0308
/// // Not copied: one proof, borrowed by the phases that touch the kernel
/// // (`clone` here is the reference's: no `IntegrityVerified` comes out).
/// fn copy(p: &nn_linux::boot::IntegrityVerified) -> nn_linux::boot::IntegrityVerified {
///     p.clone()
/// }
/// ```
///
/// ```compile_fail,E0603
/// // The object's bytes are this crate's: no load but through its loaders.
/// let bytes: &[u8] = nn_linux::sensors::ebpf_object::EBPF_BYTES;
/// ```
///
/// [`Self::for_tests`] exists only in the test builds (`test-privileged`,
/// the lab's; `test-util`, the agent's tests'): a release build has none.
#[derive(Debug)]
pub struct IntegrityVerified {
    _sealed: (),
}

impl IntegrityVerified {
    /// A proof without a boot sequence, for the privileged tests that load
    /// the object outside the agent's start (`test-privileged`; `test-util`,
    /// the agent's tests' door: `exec_sensor_live`).
    #[cfg(any(test, feature = "test-privileged", feature = "test-util"))]
    pub fn for_tests() -> Self {
        IntegrityVerified { _sealed: () }
    }
}

/// The start's position: the current phase and the steps it has done.
#[derive(Debug)]
pub struct BootSequence {
    phase: BootPhase,
    done: Vec<BootStep>,
}

impl Default for BootSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl BootSequence {
    pub fn new() -> Self {
        BootSequence {
            phase: BootPhase::Preflight,
            done: Vec::new(),
        }
    }

    pub fn phase(&self) -> BootPhase {
        self.phase
    }

    pub fn has_done(&self, step: BootStep) -> bool {
        self.done.contains(&step)
    }

    /// `step` is done; it must belong to the current phase, and not be one
    /// only its check records ([`BootStep::is_checked`], R11b, lab PR 262:
    /// those go through [`checks`]).
    ///
    /// ```
    /// use nn_linux::boot::{BootOrderError, BootSequence, BootStep};
    /// let mut boot = BootSequence::new();
    /// assert!(matches!(
    ///     boot.done(BootStep::InstallManifest),
    ///     Err(BootOrderError::Unchecked { .. })
    /// ));
    /// assert!(boot.verify_integrity().is_err());
    /// ```
    pub fn done(&mut self, step: BootStep) -> Result<(), BootOrderError> {
        if step.is_checked() {
            return Err(BootOrderError::Unchecked { step: step.name() });
        }
        self.record(step)
    }

    /// R11b (lab PR 262): a check of [`checks`] passed — the one way a
    /// [`BootStep::is_checked`] step is recorded.
    pub(crate) fn passed(&mut self, step: BootStep) -> Result<(), BootOrderError> {
        debug_assert!(step.is_checked(), "{} is recorded by done()", step.name());
        self.record(step)
    }

    fn record(&mut self, step: BootStep) -> Result<(), BootOrderError> {
        if step.phase() != self.phase {
            return Err(BootOrderError::WrongPhase {
                step: step.name(),
                belongs: step.phase().name(),
                current: self.phase.name(),
            });
        }
        if !self.done.contains(&step) {
            self.done.push(step);
        }
        Ok(())
    }

    /// Leave the current phase for `next`, the one after it, once the
    /// current one has done everything it requires.
    pub fn enter(&mut self, next: BootPhase) -> Result<(), BootOrderError> {
        if self.phase.next() != Some(next) {
            return Err(BootOrderError::OutOfOrder {
                from: self.phase.name(),
                to: next.name(),
            });
        }
        let missing: Vec<&str> = self
            .phase
            .required()
            .iter()
            .filter(|s| !self.done.contains(s))
            .map(|s| s.name())
            .collect();
        if !missing.is_empty() {
            return Err(BootOrderError::Incomplete {
                phase: self.phase.name(),
                missing: missing.join(", "),
            });
        }
        let steps: Vec<&str> = self
            .done
            .iter()
            .filter(|s| s.phase() == self.phase)
            .map(|s| s.name())
            .collect();
        info!(
            phase = self.phase.name(),
            next = next.name(),
            steps = %steps.join(","),
            "boot phase done"
        );
        self.phase = next;
        Ok(())
    }

    /// [`Self::enter`] the attach phase and get the proof the load, the pins
    /// and the attaches take (lab PR 218's `enter_attach`): only once every
    /// preflight step is recorded, the checked ones by their checks
    /// ([`checks`]). The proof's one constructor outside tests.
    pub fn verify_integrity(&mut self) -> Result<IntegrityVerified, BootOrderError> {
        self.enter(BootPhase::Attach)?;
        Ok(IntegrityVerified { _sealed: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every preflight step recorded as its check would (R11b, lab PR 262:
    /// the required steps are the checked ones, `passed` here).
    fn preflight_done() -> BootSequence {
        let mut b = BootSequence::new();
        for s in BootPhase::Preflight.required() {
            b.passed(*s).unwrap();
        }
        b
    }

    #[test]
    fn phases_are_in_order_and_each_step_in_one_phase() {
        let mut sorted = BootPhase::ORDER;
        sorted.sort();
        assert_eq!(sorted, BootPhase::ORDER);
        for p in BootPhase::ORDER {
            for s in p.required() {
                assert_eq!(s.phase(), p, "{} required by {}", s.name(), p.name());
            }
        }
        assert_eq!(BootPhase::Run.next(), None);
    }

    /// External review G-09 / Q11-03: the capability, install-manifest and
    /// audit checks come before any attach — a start that has not run one
    /// of them gets no proof (R11b, lab PR 262: nor the eBPF object's, the
    /// state directory's, the BTF offsets' or the BPF LSM's).
    #[test]
    fn no_integrity_proof_before_every_preflight_check() {
        for skipped in BootPhase::Preflight.required() {
            let mut b = BootSequence::new();
            for s in BootPhase::Preflight.required() {
                if s != skipped {
                    b.passed(*s).unwrap();
                }
            }
            let err = b.verify_integrity().unwrap_err();
            assert!(
                matches!(&err, BootOrderError::Incomplete { missing, .. } if missing == skipped.name()),
                "{err}"
            );
            assert_eq!(b.phase(), BootPhase::Preflight);
        }
        for check in [
            BootStep::EbpfObject,
            BootStep::StateDir,
            BootStep::BtfOffsets,
            BootStep::Capabilities,
            BootStep::InstallManifest,
            BootStep::AuditWritable,
            BootStep::BpfLsm,
        ] {
            assert!(BootPhase::Preflight.required().contains(&check));
            assert!(check.is_checked(), "{}", check.name());
        }
        assert!(preflight_done().verify_integrity().is_ok());
    }

    /// R11b (lab PR 262): every required step of the preflight is one only
    /// its check records, and no step of a later phase is.
    #[test]
    fn the_checked_steps_are_the_preflights_required_ones() {
        for p in BootPhase::ORDER {
            let steps: &[BootStep] = match p {
                BootPhase::Preflight => &[
                    BootStep::EbpfObject,
                    BootStep::StateDir,
                    BootStep::BtfOffsets,
                    BootStep::ChainHeads,
                    BootStep::Identity,
                    BootStep::Capabilities,
                    BootStep::InstallManifest,
                    BootStep::AuditWritable,
                    BootStep::HostHardening,
                    BootStep::BpfLsm,
                ],
                BootPhase::Attach => &[BootStep::Sensors, BootStep::AntiTamper],
                BootPhase::SelfTest => &[BootStep::DenySelfTest],
                BootPhase::Attest => &[BootStep::AgentBoot, BootStep::BootDegradations],
                BootPhase::Subsystems => &[],
                BootPhase::Run => &[BootStep::CapabilityManifest],
            };
            for s in steps {
                assert_eq!(s.phase(), p, "{}", s.name());
                assert_eq!(
                    s.is_checked(),
                    p == BootPhase::Preflight && p.required().contains(s),
                    "{}",
                    s.name()
                );
            }
        }
    }

    /// A preflight check recorded once the attach began is refused.
    #[test]
    fn a_check_after_the_attach_is_refused() {
        let mut b = preflight_done();
        let _proof = b.verify_integrity().unwrap();
        let err = b.passed(BootStep::Capabilities).unwrap_err();
        assert_eq!(
            err,
            BootOrderError::WrongPhase {
                step: "capabilities",
                belongs: "preflight",
                current: "attach",
            }
        );
        assert_eq!(
            b.done(BootStep::HostHardening).unwrap_err(),
            BootOrderError::WrongPhase {
                step: "host_hardening",
                belongs: "preflight",
                current: "attach",
            }
        );
    }

    #[test]
    fn phases_cannot_be_skipped_or_repeated() {
        let mut b = preflight_done();
        assert!(matches!(
            b.enter(BootPhase::SelfTest),
            Err(BootOrderError::OutOfOrder { .. })
        ));
        b.enter(BootPhase::Attach).unwrap();
        assert!(matches!(
            b.enter(BootPhase::Attach),
            Err(BootOrderError::OutOfOrder { .. })
        ));
        assert!(matches!(
            b.enter(BootPhase::Preflight),
            Err(BootOrderError::OutOfOrder { .. })
        ));
        // the attach must have attached
        b.done(BootStep::Sensors).unwrap();
        assert!(matches!(
            b.enter(BootPhase::SelfTest),
            Err(BootOrderError::Incomplete { .. })
        ));
        b.done(BootStep::AntiTamper).unwrap();
        b.enter(BootPhase::SelfTest).unwrap();
        b.done(BootStep::DenySelfTest).unwrap();
        b.enter(BootPhase::Attest).unwrap();
        b.done(BootStep::AgentBoot).unwrap();
        b.done(BootStep::BootDegradations).unwrap();
        b.enter(BootPhase::Subsystems).unwrap();
        b.enter(BootPhase::Run).unwrap();
        b.done(BootStep::CapabilityManifest).unwrap();
        assert_eq!(b.phase(), BootPhase::Run);
    }
}
