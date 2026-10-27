//! Lab PR 224 (CM-02): one verdict per rule per flow, across its phases.
//!
//! A TCP flow now reaches the rules up to three ways: at its connect
//! ([`FlowPhase::Connect`]), in periodic snapshots while it stays open
//! ([`FlowPhase::Snapshot`]) and at its close ([`FlowPhase::Closed`], the
//! row of `netflow.jsonl`). The rules that need no byte count judge every
//! phase, so without a ledger a C2 port flow would draw NN-L-NET-010 once
//! at the connect and again at the close, and a chain completed by a
//! precursor processed late (review 70) a second time when the flow
//! closed. The engine keeps, per flow — the connecting process and the
//! connect's timestamp, which every phase of the flow carries
//! ([`FlowKey`]) — the rules that already gave it a verdict, and skips
//! them in the later phases ([`excluded`]): the same rule never answers a
//! flow twice, and a flow gets one chain verdict (the chains tell one
//! story: a precursor, then this egress). The other rules still judge
//! the later phases: a flow killed at the connect for its port is still
//! recorded at the close for its volume. The key is forgotten at the
//! close; at most [`FLOW_LEDGER_CAP`] flows are kept (least recently
//! noted first out), only those that drew a verdict.
//!
//! Lab PR 246: a network canary trip owns its connection. The trip is the
//! connect (`Event::CanaryTripped` of `NetworkConnect`, its accessor and
//! the connect's time: the connection's [`FlowKey`]), answered by
//! NN-L-CANARY-003; every row of that connection — its connect-time row,
//! its snapshots, its close, resolved against its connect or synthesised
//! — is the same access, and no rule judges it again
//! ([`FlowLedger::owned_by_trip`]). Judged, its close drew NN-L-CHAIN-003
//! ("a canary trip, then an egress of the same process"): a second
//! Critical for one access, whenever it reached the engine after the trip
//! under another key (the KVM failure of 27/10/2026). Kept past the close
//! (a row may follow it from another task), at most [`TRIP_FLOWS_CAP`].

use std::collections::HashMap;

use nn_model::telemetry::{FlowPhase, NetFlowEvent};
use nn_model::Verdict;

use super::bounded::LazyLru;

/// Flows with a verdict remembered at once.
pub const FLOW_LEDGER_CAP: usize = 16_384;

/// Lab PR 246: connections owned by network canary trips remembered at
/// once (each trip kills its process: they are few).
pub const TRIP_FLOWS_CAP: usize = 4_096;

/// A flow, as every phase of it names it: the connecting process and the
/// connect's timestamp (`NetFlowEvent::start_ns`; a verdict's
/// `event_pid` and `timestamp_ns`).
pub type FlowKey = (u32, u64);

/// The chain family: one chain verdict per flow.
const CHAIN_PREFIX: &str = "NN-L-CHAIN-";

fn is_chain(rule_id: &str) -> bool {
    rule_id.starts_with(CHAIN_PREFIX)
}

/// Whether `rule_id` is skipped for a flow whose earlier phases drew
/// verdicts from `fired`.
pub fn excluded(rule_id: &str, fired: &[&'static str]) -> bool {
    fired.contains(&rule_id) || (is_chain(rule_id) && fired.iter().any(|f| is_chain(f)))
}

/// The rules that gave each open flow a verdict.
pub struct FlowLedger {
    fired: HashMap<FlowKey, Vec<&'static str>>,
    order: LazyLru<FlowKey>,
    cap: usize,
    /// Lab PR 246: the connections network canary trips own.
    trips: LazyLru<FlowKey>,
    trips_cap: usize,
}

impl Default for FlowLedger {
    fn default() -> Self {
        Self::with_capacity(FLOW_LEDGER_CAP)
    }
}

impl FlowLedger {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            fired: HashMap::new(),
            order: LazyLru::new(),
            cap: cap.max(1),
            trips: LazyLru::new(),
            trips_cap: TRIP_FLOWS_CAP,
        }
    }

    /// Lab PR 246: the network canary trip of the connect `key` owns the
    /// connection: none of its rows is judged again. The oldest claim
    /// makes room past [`TRIP_FLOWS_CAP`].
    pub fn claim_for_trip(&mut self, key: FlowKey) {
        if !self.trips.contains(&key) {
            while self.trips.len() >= self.trips_cap {
                if self.trips.pop_oldest().is_none() {
                    break;
                }
            }
        }
        self.trips.touch(key);
        self.forget(&key);
    }

    /// Lab PR 246: whether a network canary trip owns the flow `key`.
    pub fn owned_by_trip(&self, key: &FlowKey) -> bool {
        self.trips.contains(key)
    }

    /// The rules that already answered `key`, if any.
    pub fn fired(&self, key: &FlowKey) -> Option<Vec<&'static str>> {
        self.fired.get(key).cloned()
    }

    /// `rule_id` answered `key`.
    pub fn record(&mut self, key: FlowKey, rule_id: &'static str) {
        if !self.fired.contains_key(&key) {
            while self.fired.len() >= self.cap {
                match self.order.pop_oldest() {
                    Some(old) => {
                        self.fired.remove(&old);
                    }
                    None => break,
                }
            }
        }
        let rules = self.fired.entry(key).or_default();
        if !rules.contains(&rule_id) {
            rules.push(rule_id);
        }
        self.order.touch(key);
    }

    /// The flow is over.
    pub fn forget(&mut self, key: &FlowKey) {
        if self.fired.remove(key).is_some() {
            self.order.remove(key);
        }
    }

    /// Flows remembered.
    pub fn len(&self) -> usize {
        self.fired.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fired.is_empty()
    }
}

/// The verdict's reasoning, with what the phase of `nf` means for it: a
/// verdict on an open flow says so, one on a refused connect says that no
/// connection was made.
pub fn annotate(mut v: Verdict, nf: &NetFlowEvent) -> Verdict {
    let note = match nf.phase {
        FlowPhase::Closed => return v,
        FlowPhase::Connect => {
            "judged at the connect, while the flow is open (lab PR 224)".to_string()
        }
        FlowPhase::Snapshot => format!(
            "open-flow snapshot: the flow has been open {} s (lab PR 224)",
            nf.observed_ns.saturating_sub(nf.start_ns) / 1_000_000_000
        ),
        FlowPhase::Denied => "the connect was refused in the kernel by the socket_connect \
                              hook (--net-connect-deny): no connection was made"
            .to_string(),
    };
    v.reasoning = format!("{} [{note}]", v.reasoning);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_answers_a_flow_once_and_the_chains_once_between_them() {
        let fired = ["NN-L-NET-010_OutboundToHighRiskC2Port"];
        assert!(excluded("NN-L-NET-010_OutboundToHighRiskC2Port", &fired));
        assert!(!excluded("NN-L-NET-009_ByteAnomaly", &fired));
        assert!(!excluded("NN-L-CHAIN-001_CredReadThenEgress", &fired));
        let fired = ["NN-L-CHAIN-007_TmpCredExfilSequence"];
        assert!(excluded("NN-L-CHAIN-001_CredReadThenEgress", &fired));
        assert!(excluded("NN-L-CHAIN-002_TmpExecThenEgress", &fired));
        assert!(!excluded("NN-L-NET-008_OutboundFromTmpExec", &fired));
        assert!(!excluded("anything", &[]));
    }

    /// Lab PR 246: a trip's connection stays owned past its close (a row
    /// may follow the close from another task), the claim is bounded,
    /// oldest out, and it is the trip's connection only.
    #[test]
    fn a_trip_owns_its_connection_past_the_close_and_claims_are_bounded() {
        let mut l = FlowLedger::with_capacity(8);
        l.trips_cap = 2;
        l.record((9825, 100), "NN-L-NET-006_UncommonListener");
        l.claim_for_trip((9825, 100));
        assert!(l.owned_by_trip(&(9825, 100)));
        assert_eq!(l.fired(&(9825, 100)), None, "nothing else to remember");
        assert!(
            !l.owned_by_trip(&(9825, 101)),
            "another flow of the process"
        );
        assert!(!l.owned_by_trip(&(9826, 100)), "another process");
        l.forget(&(9825, 100));
        assert!(l.owned_by_trip(&(9825, 100)), "kept past the close");
        l.claim_for_trip((9825, 100));
        l.claim_for_trip((9827, 300));
        l.claim_for_trip((9828, 400));
        assert_eq!(l.trips.len(), 2);
        assert!(!l.owned_by_trip(&(9825, 100)), "the oldest claim goes");
        assert!(l.owned_by_trip(&(9827, 300)) && l.owned_by_trip(&(9828, 400)));
    }

    #[test]
    fn the_ledger_is_bounded_and_forgets_a_closed_flow() {
        let mut l = FlowLedger::with_capacity(2);
        l.record((1, 10), "A");
        l.record((1, 10), "A");
        l.record((1, 10), "B");
        assert_eq!(l.fired(&(1, 10)), Some(vec!["A", "B"]));
        l.record((2, 20), "A");
        l.record((3, 30), "A");
        assert_eq!(l.len(), 2);
        assert_eq!(
            l.fired(&(1, 10)),
            None,
            "the least recently noted flow goes"
        );
        l.forget(&(3, 30));
        assert_eq!(l.fired(&(3, 30)), None);
        assert_eq!(l.len(), 1);
    }
}
