//! What the decision engine does on the host it runs on (Wave 4
//! restructure, R08b, lab PR 251).
//!
//! The engine judges events; what it reads to judge them — the process
//! table, the clocks, the lineage — is its host's ([`PostureHost`], R08a,
//! lab PR 250). A few of its judges also ask the host for something no pure
//! crate can name: R018 and the ransomware tracker ask the system
//! directories' `rpm` whether a package owns a file and keep that work, and
//! the dpkg lists they read, off the agent's async runtime (tokio's
//! `block_in_place`); the tracker looks for a copy beside a deleted file in
//! the host's view of the filesystem (`/proc/1/root` from the agent's mount
//! namespace); the security-tool detector names who opened the
//! trusted-installer window and keeps the kernel's map of the tools'
//! processes (`DEFENDER_PIDS`, an aya map); the rule sets without an admin
//! dispatcher build a window that never opens. Those calls are here, as a
//! trait the host implements (the agent: `LinuxHost`, in its
//! `decision_host_linux` module, where `tokio`, `trusted_bin`,
//! `response::on_host_path` and `aya` are). Each is the call the engine's
//! code made itself before R08b, with the same arguments.
//!
//! The host is a type parameter of the engine's types, as the posture's
//! ([`crate::posture::host`]): static functions, no state, no global; what
//! the host owns (the window, the kernel map) is an associated type the
//! engine's types hold and hand back to it.

use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::anti_tamper::trusted_installer::WindowGrant;
use crate::posture::host::PostureAgent;

/// The host's calls the decision engine makes, on top of the posture's
/// ([`PostureAgent`]: the process table, the clocks, the window).
pub trait DecisionHost: PostureAgent {
    /// Run `f` where it does not hold up the host's other work (the agent:
    /// tokio's `block_in_place` on its multi-thread runtime, a plain call
    /// elsewhere). `f` may borrow from the caller.
    fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T;

    /// `rpm -qf --quiet <path>` with the system directories' `rpm`
    /// (external audit ATP-014): `Err` with the reason when there is no
    /// trusted `rpm` to run, `Ok(None)` when it could not be run, else
    /// whether a package owns `path`.
    fn rpm_owns(path: &str) -> Result<Option<bool>, String>;

    /// Run `op` on the host's view of `path` (the agent:
    /// `/proc/1/root/<path>`), or on `path` itself where that view cannot be
    /// reached at all; when it can, its error is the answer.
    fn on_host_path<T>(path: &Path, op: impl Fn(&Path) -> io::Result<T>) -> io::Result<T>;

    /// Who opened the trusted-installer window and until when, while it is
    /// open (lab PR 225).
    fn installer_grant(window: &Self::InstallerWindow) -> Option<WindowGrant>;

    /// A window that never opens: the rule sets that have no admin
    /// dispatcher to arm one (the engine's tests, the offline replay).
    fn inert_installer_window() -> Arc<Self::InstallerWindow>;

    /// The kernel's map of the security tools' processes
    /// (`DEFENDER_PIDS`, lab PR 225): the security-tool detector keeps it
    /// equal to the tools' processes it registered.
    type DefenderMap: Send + 'static;

    /// Put `pid` in the map; the error's text when the kernel refuses it.
    fn defender_map_insert(map: &mut Self::DefenderMap, pid: u32) -> Result<(), String>;

    /// Take `pid` out of the map (an absent one is no error).
    fn defender_map_remove(map: &mut Self::DefenderMap, pid: u32);
}
