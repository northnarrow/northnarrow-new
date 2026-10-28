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

pub mod deny_selftest;
pub mod lsm;
pub mod manifest;
pub mod trust;

/// R09b shim (lab PR 254; plan §4.1 rule 2, removed in R17): the phases,
/// the attach permit and the degradations of a run are nn-linux's, with
/// the eBPF loader and the sensors that take and report them.
pub use nn_linux::boot::{
    degradation, AttachPermit, BootOrderError, BootPhase, BootSequence, BootStep,
};

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

    /// The order in `main.rs` itself: every preflight check and the permit
    /// come before the first attach, the self-test right after the deny
    /// hooks, the audit log before the subsystems, the manifest before the
    /// event loop.
    #[test]
    fn main_runs_the_phases_in_order() {
        let main = include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/main.rs"));
        let at = |needle: &str| {
            main.find(needle)
                .unwrap_or_else(|| panic!("main.rs: `{needle}` not found"))
        };
        let attach = at("SensorMultiplexer::start_with_net(");
        assert!(at(".attach_anti_tamper(") > attach);
        for check in [
            "caps::boot_gate(",
            "install_manifest::check(",
            "audit_preflight::preflight_writable(",
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
        let main = include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/main.rs"));
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
        let main = include_str!(concat!(env!("NN_REPO_ROOT"), "/agent/src/main.rs"));
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
