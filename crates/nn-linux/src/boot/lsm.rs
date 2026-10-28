//! The BPF LSM gate (lab PR 218; external review AR-09 / G-11 / G-12).
//!
//! The deny hooks are BPF LSM programs. On a kernel built with
//! `CONFIG_BPF_LSM=y` but without `bpf` in the active LSM list
//! (`/sys/kernel/security/lsm`; Ubuntu's default), every one of them
//! attaches and none ever runs: the agent used to start with one WARN and
//! no self-defence at all.
//!
//! **Decision:** such a start is refused (exit 78, `EX_CONFIG`) before
//! anything attaches, unless the operator sets the degraded-mode opt-in the
//! deny-hook shortfall already uses ([`ALLOW_DEGRADED_ENV`]`=1`, itself a
//! signed `weakening_env`). Either way a signed `subsystem_degraded` names
//! the list the kernel runs. A list that cannot be read (securityfs not
//! mounted) is not a refusal: the deny self-test after the attach (the
//! agent's `boot::deny_selftest`) decides.
//!
//! Wave 4 restructure, R11b (lab PR 262): moved here from the agent's
//! `boot`, which re-exports it, so that its check records its boot step
//! ([`super::checks::bpf_lsm`]).

use std::path::Path;

pub use crate::anti_tamper::ALLOW_DEGRADED_ENV;

/// Where the kernel lists the LSMs it runs, relative to the root.
pub const ACTIVE_LSM_REL: &str = "sys/kernel/security/lsm";

/// What the active LSM list says about `bpf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BpfLsm {
    /// `bpf` is in the list (the list as read).
    Active { list: String },
    /// The list does not name `bpf`.
    Absent { list: String },
    /// The list cannot be read.
    Unknown { why: String },
}

impl BpfLsm {
    pub fn label(&self) -> &'static str {
        match self {
            BpfLsm::Active { .. } => "active",
            BpfLsm::Absent { .. } => "absent",
            BpfLsm::Unknown { .. } => "unknown",
        }
    }

    /// The list the kernel runs, when it could be read.
    pub fn list(&self) -> Option<&str> {
        match self {
            BpfLsm::Active { list } | BpfLsm::Absent { list } => Some(list),
            BpfLsm::Unknown { .. } => None,
        }
    }
}

/// Parse a `/sys/kernel/security/lsm` body (`lockdown,capability,…`).
pub fn parse(list: &str) -> BpfLsm {
    let list = list.trim().to_string();
    if list.split(',').any(|l| l.trim() == "bpf") {
        BpfLsm::Active { list }
    } else {
        BpfLsm::Absent { list }
    }
}

/// Read the active LSM list under `root` (`/` on a host).
pub fn read_in(root: &Path) -> BpfLsm {
    let path = root.join(ACTIVE_LSM_REL);
    match std::fs::read_to_string(&path) {
        Ok(body) => parse(&body),
        Err(e) => BpfLsm::Unknown {
            why: format!("{}: {e}", path.display()),
        },
    }
}

/// The gate's decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LsmGate {
    /// `bpf` runs: go on.
    Proceed,
    /// Go on, and sign `detail` (`bpf` absent under the opt-in, or the
    /// list unreadable).
    Degraded { detail: String },
    /// Refuse the start; `detail` is signed with the refusal.
    Refuse { detail: String },
}

/// Decide on `state`; `allow_degraded` is [`ALLOW_DEGRADED_ENV`]`=1`.
pub fn gate(state: &BpfLsm, allow_degraded: bool) -> LsmGate {
    match state {
        BpfLsm::Active { .. } => LsmGate::Proceed,
        BpfLsm::Absent { list } if allow_degraded => LsmGate::Degraded {
            detail: format!(
                "anti-tamper: no enforcement — `bpf` is not in the active LSM list ({list}): \
                 the deny hooks attach but the kernel never runs them; started because \
                 {ALLOW_DEGRADED_ENV}=1 (trust level L0)"
            ),
        },
        BpfLsm::Absent { list } => LsmGate::Refuse {
            detail: format!(
                "anti-tamper: `bpf` is not in the active LSM list ({list}): the deny hooks would \
                 attach and never run — start refused; add `bpf` to the list the kernel runs \
                 (docs/operator/KERNEL_COMPATIBILITY.md, \"Enabling the bpf LSM\") or set \
                 {ALLOW_DEGRADED_ENV}=1 to start without enforcement"
            ),
        },
        BpfLsm::Unknown { why } => LsmGate::Degraded {
            detail: format!(
                "anti-tamper: the active LSM list cannot be read ({why}); the deny self-test \
                 decides whether the hooks run"
            ),
        },
    }
}

/// [`ALLOW_DEGRADED_ENV`] as the process has it.
pub fn allow_degraded_from_env() -> bool {
    std::env::var(ALLOW_DEGRADED_ENV).is_ok_and(|v| v == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_is_found_anywhere_in_the_list() {
        assert!(matches!(
            parse("lockdown,capability,landlock,yama,apparmor,bpf\n"),
            BpfLsm::Active { .. }
        ));
        assert!(matches!(parse("bpf,selinux"), BpfLsm::Active { .. }));
        // Ubuntu's default list, and names that only contain the letters.
        for list in [
            "lockdown,capability,landlock,yama,apparmor",
            "bpfx,ebpf",
            "",
        ] {
            assert_eq!(
                parse(list),
                BpfLsm::Absent {
                    list: list.to_string()
                }
            );
        }
    }

    /// External review AR-09: without `bpf` the start is refused; the
    /// opt-in starts it, at L0, with a signed record either way.
    #[test]
    fn a_missing_bpf_lsm_refuses_unless_opted_in() {
        let ubuntu = parse("lockdown,capability,landlock,yama,apparmor");
        match gate(&ubuntu, false) {
            LsmGate::Refuse { detail } => {
                assert!(detail.starts_with("anti-tamper:"), "{detail}");
                assert!(detail.contains("apparmor"), "{detail}");
                assert!(detail.contains(ALLOW_DEGRADED_ENV), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        match gate(&ubuntu, true) {
            LsmGate::Degraded { detail } => {
                assert!(detail.contains("no enforcement"), "{detail}");
                assert!(detail.contains("L0"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        let debian = parse("lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm");
        assert_eq!(gate(&debian, false), LsmGate::Proceed);
        assert_eq!(gate(&debian, true), LsmGate::Proceed);
    }

    #[test]
    fn an_unreadable_list_is_left_to_the_self_test() {
        let dir = tempfile::tempdir().unwrap();
        let state = read_in(dir.path());
        assert!(matches!(state, BpfLsm::Unknown { .. }), "{state:?}");
        assert!(matches!(gate(&state, false), LsmGate::Degraded { .. }));
        std::fs::create_dir_all(dir.path().join("sys/kernel/security")).unwrap();
        std::fs::write(dir.path().join(ACTIVE_LSM_REL), "capability,bpf\n").unwrap();
        assert_eq!(
            read_in(dir.path()),
            BpfLsm::Active {
                list: "capability,bpf".to_string()
            }
        );
    }
}
