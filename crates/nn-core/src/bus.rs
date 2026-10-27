//! The event bus's types (Wave 4 restructure, R08c, lab PR 252; plan §2.3,
//! §3.4): the skeleton R12 builds the priority bus on — types only, no
//! behaviour, nothing uses them yet.
//!
//! Today every source — a pump per eBPF ring, the FIM and network drains —
//! writes into one queue, which one consumer reads, awaiting each step: a
//! flood of one class holds every other class back, and while the queue is
//! full the kernel drops the next records of every ring (plan §1.5). R12
//! gives each class of events ([`nn_model::EventClass`]) a queue of its own,
//! drained by strict priority with aging by a decision thread that never
//! awaits, with a response dispatcher of its own and a loss counter at each
//! stage of an event's path. These are the types it carries: an event in
//! its envelope, the priorities, where an event can be lost and the counts.
//! Which class an event is, each class's priority and queue, and what a full
//! queue does with a new event, are R12's.

use nn_model::{Event, EventClass, ProcessKey};

/// A priority of the bus; [`Priority::P0`] is drained first. Plan §3.4:
/// tamper (with the sensors' health) at P0, a process's life at P1, files at
/// P2, the network at P3 — strict, with aging (every 64 draws from the
/// higher classes, one from the class whose head is oldest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    P0,
    P1,
    P2,
    P3,
}

/// A source of events — an adapter's sensor, a drain — by its place in the
/// boot's sources, which the sensor contract names
/// ([`crate::contract::ClassContract::source`], R13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceId(pub u16);

/// An event on the bus, with what orders it: in its class, the order its
/// source read it in (FIFO); between classes, its time and its process
/// (plan §3.4).
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The source that read it.
    pub source: SourceId,
    /// Its place in its source's reads.
    pub seq: u64,
    /// Its class: the queue it waits in.
    pub class: EventClass,
    /// The kernel's time of the event (`CLOCK_MONOTONIC` ns).
    pub ts_ns: u64,
    /// The process it is about.
    pub key: ProcessKey,
    /// The event.
    pub event: Event,
}

/// Where on its path an event can be lost (plan §3.4), in the order it
/// meets them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LossStage {
    /// 1. The kernel's ring was full (`RING_DROPS`).
    KernelRing,
    /// 2. The kernel's budget dropped a flood.
    KernelBudget,
    /// 3. The decoder refused a record (`RejectThrottle`).
    Decode,
    /// 4. The bus's queue of a class was full.
    BusQueue(EventClass),
    /// 5. The decision came later than its class allows.
    DecisionDelay(EventClass),
    /// 6. The response queue was full.
    ResponseQueue,
    /// 7. The evidence writer's queue was full.
    EvidenceQueue,
    /// 8. The export: a record late, or missing.
    Export,
}

/// The events lost at each stage (plan §3.4) since the agent started: what
/// `nn-admin status`, the signed `telemetry_loss` rows and the heartbeat
/// report (R12; INI-14).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LossCounters {
    /// [`LossStage::KernelRing`].
    pub kernel_ring: u64,
    /// [`LossStage::KernelBudget`].
    pub kernel_budget: u64,
    /// [`LossStage::Decode`].
    pub decode: u64,
    /// [`LossStage::BusQueue`], per class.
    pub bus_queue: PerClass,
    /// [`LossStage::DecisionDelay`], per class.
    pub decision_delay: PerClass,
    /// [`LossStage::ResponseQueue`].
    pub response_queue: u64,
    /// [`LossStage::EvidenceQueue`].
    pub evidence_queue: u64,
    /// [`LossStage::Export`].
    pub export: u64,
}

/// A count for each class of events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerClass {
    pub tamper: u64,
    pub process: u64,
    pub file: u64,
    pub network: u64,
    pub health: u64,
}
