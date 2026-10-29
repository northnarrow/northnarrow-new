//! The signed audit log, for what starts before the start binds it (Wave 4
//! restructure, R11c, lab PR 264).
//!
//! The samplers the eBPF load starts — the ring-drop counters, the deny
//! hooks' fail-open counters, the exploit guard's — run before the start
//! hands them the audit log (`boot::evidence`'s attest phase and its late
//! binding, `wire`). Each module kept the log in a process-wide `OnceLock`
//! that a setter filled (`set_audit_log`). Each now holds a clone of a
//! [`LateAudit`] made where it is built and returned to the start, which
//! binds it at the same point of the start as the setter ran: before the
//! binding a sampler signs nothing, after it every row, as before.

use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;

use crate::audit::AuditLog;

/// The agent's signed audit log, shared.
pub type AuditHandle = Arc<Mutex<AuditLog>>;

/// A slot for the audit log, bound once. Clones share it.
#[derive(Clone, Default)]
pub struct LateAudit(Arc<OnceLock<AuditHandle>>);

impl LateAudit {
    /// An empty slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `log` (`None`: the start runs without one, nothing is bound).
    /// The first binding stays, as the setters' `OnceLock::set` did.
    pub fn bind(&self, log: Option<AuditHandle>) {
        if let Some(log) = log {
            let _ = self.0.set(log);
        }
    }

    /// The log, once bound.
    pub fn get(&self) -> Option<&AuditHandle> {
        self.0.get()
    }
}

impl std::fmt::Debug for LateAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LateAudit")
            .field("bound", &self.0.get().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AgentSigningKey;

    fn log(dir: &std::path::Path) -> AuditHandle {
        std::fs::create_dir_all(dir).unwrap();
        let key = AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig")).unwrap();
        Arc::new(Mutex::new(
            AuditLog::open(&dir.join("audit.log"), key, [0x64; 16]).unwrap(),
        ))
    }

    /// Unbound until bound, the first binding kept, shared by its clones,
    /// and a slot of its own for each `new` (two samplers, or two tests,
    /// never see each other's log).
    #[test]
    fn a_slot_is_bound_once_and_shared_by_its_clones() {
        let dir = tempfile::TempDir::new().unwrap();
        let (a, b) = (log(&dir.path().join("a")), log(&dir.path().join("b")));
        let slot = LateAudit::new();
        let clone = slot.clone();
        assert!(clone.get().is_none());
        slot.bind(None);
        assert!(clone.get().is_none(), "nothing to bind");
        slot.bind(Some(Arc::clone(&a)));
        assert!(Arc::ptr_eq(clone.get().unwrap(), &a));
        clone.bind(Some(b));
        assert!(
            Arc::ptr_eq(slot.get().unwrap(), &a),
            "the first binding stays"
        );
        assert!(LateAudit::new().get().is_none(), "another slot is its own");
    }
}
