//! NN-L-AT-001 — every anti-tamper denial becomes a signed detection.
//!
//! The kernel refuses the action either way (`task_kill`, `ptrace`,
//! `inode_*`, `bpf_map`, `bpf` hooks); this rule makes the attempt part of
//! the signed detection chain instead of a journal line only, so the
//! adversarial check (`deploy/lab/adversarial/anti-tamper.sh`) finds every
//! refused case in `detections.jsonl`. Posture still reacts through the
//! `AntiTamperDenial` trigger (COMBAT / INVESTIGATE) — or, for a signal
//! systemd relayed, `RelayedTamperAttempt` (ENGAGED). Log only: the attempt
//! already failed, and killing the actor is the ladder's call.
//!
//! Not in the engine's rule list: `process_event` short-circuits every
//! `FsProtectDenial` before the engine (a kernel deny is not re-evaluated)
//! and calls this rule directly in that arm.

use nn_model::{Event, FsProtectOperation, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

pub struct NnLAt001AntiTamperDenial;

impl Rule for NnLAt001AntiTamperDenial {
    fn id(&self) -> &'static str {
        "NN-L-AT-001_AntiTamperDenial"
    }
    fn name(&self) -> &'static str {
        "Attempt on the agent refused by an anti-tamper hook"
    }
    fn category(&self) -> &'static str {
        "anti_tamper"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::DefenseImpairment, "T1685"),
            AttackRef::new(Tactic::Stealth, "T1055.008"),
            AttackRef::new(Tactic::Stealth, "T1055.009"),
            AttackRef::new(Tactic::CredentialAccess, "T1552.004"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::FsProtectDenial {
            pid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } = event
        else {
            return None;
        };
        let what = match operation {
            // External audit EBPF-001: systemd only relays root's request.
            FsProtectOperation::Signal if *pid == 1 => format!(
                "to deliver signal {target_dev} to protected pid {target_ino} on behalf of a \
                 `systemctl stop` / `kill` / `restart` outside a trusted-installer window"
            ),
            FsProtectOperation::Signal => {
                format!("signal {target_dev} to protected pid {target_ino} (kill / pkill)")
            }
            FsProtectOperation::Ptrace => format!(
                "ptrace attach (mode {target_dev:#x}) on protected pid {target_ino} — debugger, \
                 /proc/<pid>/mem or process_vm_readv/writev"
            ),
            FsProtectOperation::BpfMap => {
                format!("write handle on the agent's BPF map id {target_ino}")
            }
            FsProtectOperation::BpfLink => {
                format!("handle to the agent's BPF link (id {target_ino}, 0 = through the pin)")
            }
            // Review 82: a loaded image lets root reboot at once into a
            // kernel without the agent.
            FsProtectOperation::Kexec => "to load a kexec kernel image (kexec -l / -p / \
                 systemctl kexec) outside the trusted-installer window: a loaded image \
                 boots a kernel without the agent"
                .to_string(),
            // External audit EVD-001: the key that signs every evidence chain.
            FsProtectOperation::Read => format!(
                "to read the agent's private signing key (inode {target_dev}:{target_ino}), which \
                 signs every evidence chain"
            ),
            // External audit EBPF-015: the target of a new entry is the
            // directory it was to be made in.
            FsProtectOperation::Create
            | FsProtectOperation::Link
            | FsProtectOperation::Symlink
            | FsProtectOperation::Mkdir
            | FsProtectOperation::Mknod => format!(
                "a new entry ({operation}) in the agent's protected directory (inode \
                 {target_dev}:{target_ino}) outside a trusted-installer window"
            ),
            FsProtectOperation::Xattr => format!(
                "to change an extended attribute or ACL of protected inode \
                 {target_dev}:{target_ino}"
            ),
            other => format!("{other} on protected inode {target_dev}:{target_ino}"),
        };
        let reasoning = format!(
            "`{comm}` attempted {what}; the kernel refused it. An attempt on the sensor itself is \
             the clearest intent signal there is."
        );
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::High,
            &reasoning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denial(op: FsProtectOperation) -> Event {
        Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: "bash".into(),
            target_dev: 9,
            target_ino: 709,
            operation: op,
            timestamp_ns: 1,
        }
    }

    /// Review 82: the kexec wire byte decodes to `Kexec`, and an unknown
    /// byte stays unknown (a missing import once turned the arm into a
    /// catch-all binding).
    #[test]
    fn kexec_wire_byte_decodes_and_unknown_stays_unknown() {
        use common::wire::FS_OP_KEXEC;
        assert_eq!(
            FsProtectOperation::from_wire(FS_OP_KEXEC),
            FsProtectOperation::Kexec
        );
        assert_eq!(
            FsProtectOperation::from_wire(200),
            FsProtectOperation::Unknown(200)
        );
    }

    #[test]
    fn every_denial_kind_is_a_high_log_verdict() {
        for op in [
            FsProtectOperation::Signal,
            FsProtectOperation::Ptrace,
            FsProtectOperation::Unlink,
            FsProtectOperation::BpfMap,
            FsProtectOperation::BpfLink,
            FsProtectOperation::Kexec,
            FsProtectOperation::Create,
            FsProtectOperation::Link,
            FsProtectOperation::Symlink,
            FsProtectOperation::Mkdir,
            FsProtectOperation::Mknod,
            FsProtectOperation::Xattr,
        ] {
            let v = NnLAt001AntiTamperDenial
                .evaluate(&denial(op))
                .expect("verdict");
            assert_eq!(v.severity, Severity::High);
            assert!(matches!(v.action, ResponseAction::Log));
        }
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Signal))
            .unwrap();
        assert!(v.reasoning.contains("signal 9 to protected pid 709"));
    }

    /// External audit EBPF-015: a refused new entry names the directory as
    /// where it was to be made, and the operation by its kernel name.
    #[test]
    fn a_refused_new_entry_names_the_directory() {
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Mkdir))
            .expect("verdict");
        assert!(v.reasoning.contains("new entry (mkdir)"), "{}", v.reasoning);
        assert!(
            v.reasoning.contains("directory (inode 9:709)"),
            "{}",
            v.reasoning
        );
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Xattr))
            .expect("verdict");
        assert!(
            v.reasoning.contains("extended attribute"),
            "{}",
            v.reasoning
        );
    }

    /// External audit EBPF-001: a signal PID 1 relayed names the request,
    /// not systemd, as what was refused.
    #[test]
    fn a_relayed_signal_names_the_systemctl_request() {
        let mut e = denial(FsProtectOperation::Signal);
        if let Event::FsProtectDenial { pid, comm, .. } = &mut e {
            *pid = 1;
            *comm = "systemd".into();
        }
        let v = NnLAt001AntiTamperDenial.evaluate(&e).expect("verdict");
        assert!(v.reasoning.contains("systemctl stop"), "{}", v.reasoning);
        assert!(v.reasoning.contains("trusted-installer window"));
    }
}
