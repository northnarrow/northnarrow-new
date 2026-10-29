//! The exec guards' kernel configuration, which the eBPF loader writes once
//! the exec sensor is attached (Wave 4 restructure, R09b, lab PR 254: cut
//! verbatim from `sensors::multiplexer`'s load, which calls it through its
//! [`ExecGuards`](crate::sensors::multiplexer::ExecGuards) seam). The exec
//! quarantine (lab PR 223) and the exec policy (lab PR 226) are the
//! agent's.
//!
//! R11c (lab PR 264): the guards are an instance the start makes with their
//! configuration and hands to the load, which installs them and leaves
//! them the kernel objects they took, for the start's tasks phase to start
//! their controllers with. Both were process-wide statics
//! (`execq::configure`, `execpol::configure`, the modules' `KERNEL`).

use aya::Ebpf;
use tracing::error;

use crate::sensors::multiplexer::ExecGuards;

/// The agent's exec guards: the exec quarantine, then the exec policy.
pub struct AgentExecGuards {
    /// The exec quarantine's configuration (from the command line).
    pub execq: crate::execq::Config,
    /// The exec policy's (its signed table read at the attach).
    pub execpol: crate::execpol::Config,
    /// What the install took for each controller (`None`: it does not run).
    pub execq_kernel: Option<crate::execq::kernel::Kernel>,
    pub execpol_kernel: Option<crate::execpol::kernel::Kernel>,
}

impl AgentExecGuards {
    /// The guards of `execq` and `execpol`, not installed yet.
    pub fn new(execq: crate::execq::Config, execpol: crate::execpol::Config) -> Self {
        Self {
            execq,
            execpol,
            execq_kernel: None,
            execpol_kernel: None,
        }
    }
}

impl ExecGuards for AgentExecGuards {
    fn install(&mut self, ebpf: &mut Ebpf, exec_on_lsm: bool) {
        // Lab PR 223 (EXPERIMENTAL): the exec quarantine's kernel
        // configuration, once the exec sensor's mode is known — written OFF
        // too, then frozen — and its maps for the controller. Not fatal:
        // an unwritten configuration is OFF, the kernel holds nothing.
        match crate::execq::install(ebpf, &self.execq, exec_on_lsm) {
            Ok(kernel) => self.execq_kernel = kernel,
            Err(e) => {
                error!(
                    error = format!("{e:#}"),
                    "exec quarantine: kernel configuration failed — the guard is off"
                );
                if self.execq.mode != crate::execq::Mode::Off {
                    crate::execq::fail(format!("kernel configuration failed: {e:#}"));
                }
            }
        }
        // Lab PR 226 (EXPERIMENTAL): the exec policy — its environment and
        // mapping programs, then its kernel configuration, written OFF too
        // and frozen. Not fatal: an unwritten configuration is OFF.
        let execq_on = self.execq.mode != crate::execq::Mode::Off
            && !crate::execq::state().starts_with("degraded");
        match crate::execpol::install(ebpf, &self.execpol, execq_on, exec_on_lsm) {
            Ok(kernel) => self.execpol_kernel = kernel,
            Err(e) => {
                error!(
                    error = format!("{e:#}"),
                    "exec policy: kernel configuration failed — the policy is off"
                );
                if self.execpol.mode != crate::execpol::Mode::Off {
                    crate::execpol::fail(format!("kernel configuration failed: {e:#}"));
                }
            }
        }
    }
}
