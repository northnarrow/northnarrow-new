//! The sensor contract's types (Wave 4 restructure, R08c, lab PR 252; plan
//! §2.3, §3.6): the skeleton R13 builds the signed contract on — types only,
//! no behaviour, nothing uses them yet.
//!
//! For each class of events ([`nn_model::EventClass`]) the agent will
//! declare where its events come from, what decides on one before the
//! operation it reports completes, what a failure of its source means, its
//! budget, what its records truncate and where its losses are counted; and
//! for each source, the state it is in. R13 builds that declaration from
//! the real attaches and `telemetry_probe`'s self-test, signs it in the audit
//! chain, shows it in `nn-admin status`, and signs every change of it. The
//! manifest that carries it is the boot's signed capability manifest (lab PR
//! 218: the agent's `boot::manifest`, op `capability_manifest`, the
//! sensors' attach points, the deny hooks, the degradations), which R13
//! extends: it has no type here.

use std::time::Duration;

use nn_model::EventClass;

use crate::bus::LossStage;

/// What a class of events is promised (plan §3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassContract {
    /// The class.
    pub class: EventClass,
    /// Where its events come from: the attach point (`bpf-lsm:file_open`,
    /// `tracepoint:sys_enter_openat`).
    pub source: String,
    /// What decides on an event before the operation it reports completes.
    pub sync_verdict: SyncVerdict,
    /// What a failure of its source means.
    pub on_failure: FailureMode,
    /// The events a second its source is held to; past them the source is
    /// [`SourceState::OverBudget`]. `None`: no budget.
    pub budget: Option<u32>,
    /// What its records cut (argv at 511 bytes, a QNAME at 288).
    pub truncation: Vec<Truncation>,
    /// Where its source's losses are counted.
    pub loss_counter: LossStage,
}

/// What decides on an event before the operation it reports completes
/// (plan §3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncVerdict {
    /// Nothing: the event reports what happened.
    None,
    /// The kernel denies the operation, on this hook.
    KernelDeny { hook: String },
    /// User space decides within this deadline, the operation held.
    UserDeadline { deadline: Duration },
}

/// What a failure of a class's source means (plan §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureMode {
    /// The operations go on, unchecked.
    FailOpen,
    /// The operations are refused.
    FailClosed,
    /// Nothing of the class is seen until the source is back.
    Blind,
}

/// A field a record cuts at a bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Truncation {
    /// The field (`argv`, `qname`).
    pub field: String,
    /// The bytes kept.
    pub max_bytes: u32,
}

/// The state a source is in (plan §2.3), as the contract reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceState {
    /// Not on this host: no hook, no tracepoint, nothing to attach.
    Unavailable,
    /// Attached, and not invoked since: the self-test did not reach it.
    AttachedNotInvoked,
    /// Delivering, and losing records.
    Lossy,
    /// Past its budget.
    OverBudget,
    /// Switched off by an administrator.
    DisabledByAdmin,
    /// Its adapter stopped: the pump or the drain ended.
    AdapterTerminated,
    /// Attached, invoked, nothing lost.
    Ok,
}
