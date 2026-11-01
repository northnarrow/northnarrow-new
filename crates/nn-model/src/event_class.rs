//! The class of an event (Wave 4 restructure, R08c, lab PR 252; plan §2.3,
//! §3.4): what the priority bus queues an event by (R12), and what the
//! sensor contract declares a source for (R13, lab PR 271:
//! `nn_core::contract`). A type only: which class each event is, and what
//! each class is promised, are those lots'.

use serde::{Deserialize, Serialize};

/// A class of events. Plan §3.4 groups them: tamper (`FsProtectDenial`,
/// `BpfSyscall`, `ModuleLoad`, `SensorFlood`) with the sensors' health, a
/// process's life (`ProcessSpawn`, `ExecCheck`, `IoUring`), files (`Fim`,
/// `MassWrite`, `FileOpen`), the network (`TcpConnect`, `DnsQuery`,
/// `DnsFlood`, `NetFlow`, `NetListener`); the events added since the plan
/// are placed by R12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

impl EventClass {
    /// Every class, in the bus's order (R13: the sensor contract has an
    /// entry for each, `nn_core::contract::class_contracts`).
    pub const ALL: [EventClass; 5] = [
        EventClass::Tamper,
        EventClass::Process,
        EventClass::File,
        EventClass::Network,
        EventClass::Health,
    ];

    /// Its name in the signed manifest and in `nn-admin`'s output.
    pub const fn name(self) -> &'static str {
        match self {
            EventClass::Tamper => "tamper",
            EventClass::Process => "process",
            EventClass::File => "file",
            EventClass::Network => "network",
            EventClass::Health => "health",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R13: `ALL` holds each class once, in the bus's order. The match is
    /// exhaustive: a new class does not compile here until it is given its
    /// place, and the place must be its index in `ALL`.
    #[test]
    fn all_holds_every_class_once() {
        let place = |c: EventClass| match c {
            EventClass::Tamper => 0,
            EventClass::Process => 1,
            EventClass::File => 2,
            EventClass::Network => 3,
            EventClass::Health => 4,
        };
        for (i, c) in EventClass::ALL.iter().enumerate() {
            assert_eq!(place(*c), i, "{c:?}");
        }
        assert_eq!(EventClass::ALL.len(), place(EventClass::Health) + 1);
        let mut names: Vec<&str> = EventClass::ALL.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), EventClass::ALL.len());
        assert_eq!(
            serde_json::to_string(&EventClass::Network).unwrap(),
            "\"network\""
        );
    }
}
