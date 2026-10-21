//! Boot integrity (lab PR 218; external review G-09, G-11, G-12, AR-09,
//! P0 C-13, P0 C-14; `docs/operator/BOOT_INTEGRITY.md`).
//!
//! The agent's start as typed phases, in an order the code enforces
//! instead of comments in `main()`:
//!
//! 1. [`BootPhase::Preflight`] — checks only, nothing is loaded into the
//!    kernel: the embedded eBPF object, the BTF offsets, the capabilities,
//!    the install manifest, the audit log's writability, the active LSMs
//!    ([`lsm`]). A refusal here leaves the host as it was.
//! 2. [`BootPhase::Attach`] — the eBPF object, the sensors and the deny
//!    hooks. Only an [`AttachPermit`] opens it, and only
//!    [`BootSequence::enter_attach`] gives one, once every preflight check
//!    has run: the sensor and anti-tamper attach take it as an argument.
//! 3. [`BootPhase::SelfTest`] — one deny hook exercised against the agent
//!    itself ([`deny_selftest`]): "attached but never run" is measured, not
//!    assumed.
//! 4. [`BootPhase::Attest`] — the signed audit log opens (`agent_boot`),
//!    then every degradation found so far is signed ([`degradation`]).
//! 5. [`BootPhase::Subsystems`] — what needs the audit log: the FIM
//!    observers, the file-open sensor, the drains, the admin socket.
//! 6. [`BootPhase::Run`] — the capability manifest and the trust level are
//!    signed ([`manifest`], [`trust`]); then the event loop.
//!
//! A step recorded in the wrong phase, a phase skipped or left with a
//! required step missing is a [`BootOrderError`]: the start stops there.

pub mod degradation;
pub mod deny_selftest;
pub mod lsm;
pub mod manifest;
pub mod trust;

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

/// Lab PR 231: give the kernel back the heap the boot freed, once, after
/// READY. The attach parses the vmlinux BTF several times (aya's loader, the
/// LSM, fentry and FIM attaches), each a transient of about 15 MB; from aya
/// 0.14 (aya-obj 0.3, whose `BtfType` grew from 48 to 72 bytes) glibc keeps
/// those pages after the free, and the idle agent's RSS rose by about 17 MB
/// (perf gate: `agent_rss_idle_kib` +47 %, `agent_rss_load_kib` +38 %
/// against the same guest's `main`). `malloc_trim(0)` releases only free
/// memory. Returns whether glibc released any; `false` off glibc.
pub fn release_boot_heap() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: malloc_trim takes glibc's own arena locks and touches only
        // free chunks; no Rust allocation or invariant is involved.
        unsafe { libc::malloc_trim(0) == 1 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
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

    /// The order in `main.rs` itself: every preflight check and the permit
    /// come before the first attach, the self-test right after the deny
    /// hooks, the audit log before the subsystems, the manifest before the
    /// event loop.
    #[test]
    fn main_runs_the_phases_in_order() {
        let main = include_str!("../main.rs");
        let at = |needle: &str| {
            main.find(needle)
                .unwrap_or_else(|| panic!("main.rs: `{needle}` not found"))
        };
        let attach = at("SensorMultiplexer::start_with_net(");
        assert!(at(".attach_anti_tamper(") > attach);
        for check in [
            "caps::boot_gate(",
            "install_manifest::check(",
            "audit::preflight_writable(",
            "boot::lsm::gate(",
            "boot.done(BootStep::Capabilities)",
            "boot.done(BootStep::InstallManifest)",
            "boot.done(BootStep::AuditWritable)",
            "boot.done(BootStep::BpfLsm)",
            "boot.enter_attach()",
        ] {
            assert!(at(check) < attach, "`{check}` after the attach");
        }
        let selftest = at("boot::deny_selftest::run(");
        assert!(selftest > at(".attach_anti_tamper("));
        let audit_open = at("AuditLog::open(&cli.audit_log_file, key, agent_id) {");
        assert!(audit_open > selftest);
        assert!(at("boot.enter(BootPhase::Attest)") < audit_open);
        assert!(at("boot.enter(BootPhase::Subsystems)") > audit_open);
        assert!(
            at("RuleEngine::with_default_rules_and_net(") > at("boot.enter(BootPhase::Subsystems)"),
            "the rule engine in the subsystems phase, after the audit log"
        );
        let manifest = at("boot::manifest::sign(");
        assert!(manifest > at("boot.enter(BootPhase::Run)"));
        assert!(manifest < at("sd_notify::ready()"));
        assert!(at("boot.done(BootStep::CapabilityManifest)") > manifest);
    }

    /// Lab PR 231: the boot's heap is released once, after READY — after
    /// every attach (the BTF parses whose pages glibc kept) and only once.
    #[test]
    fn main_releases_the_boot_heap_after_ready() {
        let main = include_str!("../main.rs");
        let release = main
            .find("boot::release_boot_heap()")
            .expect("main.rs releases the boot heap");
        assert_eq!(main.matches("boot::release_boot_heap()").count(), 1);
        assert!(release > main.find("sd_notify::ready()").expect("READY"));
        assert!(release > main.find("boot::manifest::sign(").expect("manifest"));
    }

    /// Lab PR 231: only free memory goes back: what is still allocated is
    /// intact after the release.
    #[test]
    fn releasing_the_boot_heap_keeps_live_allocations() {
        let live: Vec<u64> = (0..200_000).collect();
        let freed: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; 64 * 1024]).collect();
        drop(freed);
        let released = release_boot_heap();
        if cfg!(not(all(target_os = "linux", target_env = "gnu"))) {
            assert!(!released);
        }
        assert!(live.iter().enumerate().all(|(i, v)| *v == i as u64));
    }

    /// External review P0 C-14: the network drain is spawned whatever the
    /// netflow log — without it the flows reach the rules unpersisted, and
    /// the gap is signed (`net::drain` tests the record path without a log).
    #[test]
    fn main_runs_the_net_drain_without_its_log() {
        let main = include_str!("../main.rs");
        assert!(
            !main.contains("if let Some(netflow_db) = netflow_db_opt"),
            "the drain waits for the netflow log again"
        );
        let open = main.find("NetFlowDb::open(").expect("the netflow log");
        let spawn = main[open..]
            .find("drain_loop(")
            .map(|i| open + i)
            .expect("the drain");
        assert!(
            main[open..spawn].contains("\"net_drain\""),
            "a netflow log that cannot be opened is a signed degradation"
        );
    }
}
