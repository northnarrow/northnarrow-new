//! The boot sequence's typed phases and the proof that every preflight
//! check ran (lab PR 218): the permit the eBPF loader and the deny hooks'
//! attach take, the degradations of a run, and the sensors' attach points
//! the boot's capability manifest lists — what the sensors take and report
//! (Wave 4 restructure, R09b, lab PR 254: cut verbatim from the agent's
//! `boot`, which re-exports them; its deny self-test, BPF LSM gate, trust
//! level and signed manifest stay in the agent).

pub mod degradation;
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
    /// The audit log can be opened for append.
    AuditWritable,
    /// The host hardening table.
    HostHardening,
    /// `bpf` in the active LSMs, or the degraded-mode opt-in ([`lsm`]).
    BpfLsm,
    /// The eBPF object loaded and the sensors attached.
    Sensors,
    /// The deny hooks attached and the agent registered.
    AntiTamper,
    /// The deny self-test ran ([`deny_selftest`]).
    DenySelfTest,
    /// The signed `agent_boot` entry is written.
    AgentBoot,
    /// The degradations found before the audit log opened are signed.
    BootDegradations,
    /// The capability manifest is signed.
    CapabilityManifest,
}

impl BootStep {
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
}

/// The proof that every preflight check ran: the only way into the kernel.
/// [`crate::sensors::SensorMultiplexer::start_with_net`] and
/// [`crate::sensors::SensorMultiplexer::attach_anti_tamper`] take it, and
/// [`BootSequence::enter_attach`] is its only constructor outside tests.
#[derive(Debug)]
pub struct AttachPermit {
    _private: (),
}

impl AttachPermit {
    /// A permit without a boot sequence, for the privileged tests that load
    /// the object outside the agent's start.
    #[cfg(any(test, feature = "test-privileged"))]
    pub fn for_tests() -> Self {
        AttachPermit { _private: () }
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

    /// `step` is done; it must belong to the current phase.
    pub fn done(&mut self, step: BootStep) -> Result<(), BootOrderError> {
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

    /// [`Self::enter`] the attach phase and get the permit the attach takes.
    pub fn enter_attach(&mut self) -> Result<AttachPermit, BootOrderError> {
        self.enter(BootPhase::Attach)?;
        Ok(AttachPermit { _private: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preflight_done() -> BootSequence {
        let mut b = BootSequence::new();
        for s in BootPhase::Preflight.required() {
            b.done(*s).unwrap();
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
    /// of them gets no permit.
    #[test]
    fn no_attach_permit_before_every_preflight_check() {
        for skipped in BootPhase::Preflight.required() {
            let mut b = BootSequence::new();
            for s in BootPhase::Preflight.required() {
                if s != skipped {
                    b.done(*s).unwrap();
                }
            }
            let err = b.enter_attach().unwrap_err();
            assert!(
                matches!(&err, BootOrderError::Incomplete { missing, .. } if missing == skipped.name()),
                "{err}"
            );
            assert_eq!(b.phase(), BootPhase::Preflight);
        }
        for check in [
            BootStep::Capabilities,
            BootStep::InstallManifest,
            BootStep::AuditWritable,
            BootStep::BpfLsm,
        ] {
            assert!(BootPhase::Preflight.required().contains(&check));
        }
        assert!(preflight_done().enter_attach().is_ok());
    }

    /// A preflight check recorded once the attach began is refused.
    #[test]
    fn a_check_after_the_attach_is_refused() {
        let mut b = preflight_done();
        let _permit = b.enter_attach().unwrap();
        let err = b.done(BootStep::Capabilities).unwrap_err();
        assert_eq!(
            err,
            BootOrderError::WrongPhase {
                step: "capabilities",
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
