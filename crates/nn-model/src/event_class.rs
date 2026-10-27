//! The class of an event (Wave 4 restructure, R08c, lab PR 252; plan §2.3,
//! §3.4): what the priority bus queues an event by (R12), and what the
//! sensor contract declares a source for (R13). A type only: which class
//! each event is, and what each class is promised, are those lots'.

/// A class of events. Plan §3.4 groups them: tamper (`FsProtectDenial`,
/// `BpfSyscall`, `ModuleLoad`, `SensorFlood`) with the sensors' health, a
/// process's life (`ProcessSpawn`, `ExecCheck`, `IoUring`), files (`Fim`,
/// `MassWrite`, `FileOpen`), the network (`TcpConnect`, `DnsQuery`,
/// `DnsFlood`, `NetFlow`, `NetListener`); the events added since the plan
/// are placed by R12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventClass {
    /// An attempt on the agent or its host's defences.
    Tamper,
    /// A process's life.
    Process,
    /// Files.
    File,
    /// The network.
    Network,
    /// The sensors' own health.
    Health,
}
