//! The Linux host of the decision engine: the calls of nn-core's
//! [`DecisionHost`] (Wave 4 restructure, R08b, lab PR 251), as the engine's
//! code made them itself before — the work kept off the async runtime
//! (`runtime::off_the_runtime`, tokio's `block_in_place`), the system
//! directories' `rpm` (`trusted_bin`), the host's view of a path
//! (`response::on_host_path`, `/proc/1/root`), the trusted-installer window
//! (`anti_tamper::trusted_installer`), the kernel's `DEFENDER_PIDS` (an aya
//! map), with the same arguments. The host is the chains' and the
//! posture's one ([`LinuxHost`], `chain_host_linux`): one type, the agent's.

use std::io;
use std::path::Path;
use std::sync::Arc;

use nn_core::anti_tamper::trusted_installer::WindowGrant;
use nn_core::decision::host::DecisionHost;

use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::chain_host_linux::LinuxHost;

impl DecisionHost for LinuxHost {
    fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T {
        crate::runtime::off_the_runtime(f)
    }

    /// `trusted_bin::resolve("rpm")`, then `rpm -qf --quiet <path>` with its
    /// output discarded.
    fn rpm_owns(path: &str) -> Result<Option<bool>, String> {
        let rpm = crate::trusted_bin::resolve("rpm").map_err(|e| e.to_string())?;
        let status = rpm
            .command()
            .args(["-qf", "--quiet", path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        Ok(status.ok().map(|s| s.success()))
    }

    fn on_host_path<T>(path: &Path, op: impl Fn(&Path) -> io::Result<T>) -> io::Result<T> {
        crate::response::on_host_path(path, op)
    }

    fn installer_grant(window: &TrustedInstallerOverride) -> Option<WindowGrant> {
        window.current_grant()
    }

    fn inert_installer_window() -> Arc<TrustedInstallerOverride> {
        TrustedInstallerOverride::inert_arc()
    }

    type DefenderMap = crate::impair::DefenderMap;

    fn defender_map_insert(map: &mut Self::DefenderMap, pid: u32) -> Result<(), String> {
        map.insert(pid, 1, 0).map_err(|e| e.to_string())
    }

    fn defender_map_remove(map: &mut Self::DefenderMap, pid: u32) {
        let _ = map.remove(&pid);
    }
}
