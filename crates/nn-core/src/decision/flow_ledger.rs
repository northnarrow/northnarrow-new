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
//! Bug hunt 1.3, BUG45 (decision of 10/11/2026): an answer that ran no
//! response does not keep a stronger one from the flow.
//!
//! - A match the signed per-rule policy turns `off`, or whose exemption
//!   covers the actor, leaves nothing in the ledger: it is no answer. An
//!   `off` NN-L-CHAIN-002 at the connect used to take the flow's chain
//!   verdict, so the credential read the process made while the session was
//!   open drew no CHAIN-001/CHAIN-007 kill at the snapshot.
//! - The chain verdict of a flow is held by a chain answer that **acted**
//!   ([`Answer::acted`]). One that is only a record — an aged precursor's
//!   High `Log` (external audit NETR-014), an `alert` or `audit` mode, the
//!   `Log` of NN-L-CHAIN-008, a response held by a switch or the legacy
//!   ceiling — keeps the chains judging the flow's later phases, and a chain
//!   verdict that acts (the same chain's included: an aged read at the
//!   connect, a fresh one on the open session) still answers it
//!   ([`excluded`]). A chain verdict that would again be only a record is
//!   dropped ([`suppressed`]): one chain story per flow, as before.
//! - Any other rule still answers a flow once, whatever its answer did.
//!
//! An exempt match is judged again in the flow's later phases, so its
//! audit record may be written again (the detection budget bounds it), and
//! an exemption revoked meanwhile (lot 281: code injected into the
//! process) no longer hides the flow from the rule.
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
use super::combine::{Applied, RuleMatch};

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

/// One answer a flow drew in an earlier phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub rule_id: &'static str,
    /// Its response ran: a match that acts once the policy and the legacy
    /// ceiling are applied (`RuleMatch::acts` in the decision), not a record
    /// (bug hunt 1.3, BUG45).
    pub acted: bool,
}

/// Whether `rule_id` is skipped, before it is judged, for a flow whose
/// earlier phases drew the answers `fired`: a rule that answered it, a
/// chain once a chain's answer acted on it (BUG45: a chain answer that was
/// only a record leaves the chains to [`suppressed`]).
pub fn excluded(rule_id: &str, fired: &[Answer]) -> bool {
    if is_chain(rule_id) {
        fired.iter().any(|a| a.acted && is_chain(a.rule_id))
    } else {
        fired.iter().any(|a| a.rule_id == rule_id)
    }
}

/// Bug hunt 1.3, BUG45: whether the match of `rule_id`, judged on a flow
/// whose earlier phases drew the answers `fired`, is dropped — a chain's
/// match that does not act (`acts`: its response would run, after the
/// policy) when a chain already answered the flow. Answers of the same
/// strength stay one per flow; a chain's that acts may still answer it.
pub fn suppressed(rule_id: &str, acts: bool, fired: &[Answer]) -> bool {
    is_chain(rule_id) && !acts && fired.iter().any(|a| is_chain(a.rule_id))
}

/// Bug hunt 1.3, BUG45: the answer a decision's match gives a flow, and
/// whether its response runs (the legacy ceiling applied) — none for a
/// match the signed per-rule policy turned `off` or whose exemption covers
/// the actor.
pub fn answer_of(m: &RuleMatch) -> Option<Answer> {
    (!matches!(m.applied, Applied::Off | Applied::Exempt(_))).then_some(Answer {
        rule_id: m.rule_id,
        acted: m.acts(),
    })
}

/// The rules that gave each open flow a verdict.
pub struct FlowLedger {
    fired: HashMap<FlowKey, Vec<Answer>>,
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

    /// The answers `key` already drew, if any.
    pub fn fired(&self, key: &FlowKey) -> Option<Vec<Answer>> {
        self.fired.get(key).cloned()
    }

    /// `rule_id` answered `key`; `acted`: its response ran ([`Answer`]). A
    /// rule's later answer that acted marks its earlier one so.
    pub fn record(&mut self, key: FlowKey, rule_id: &'static str, acted: bool) {
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
        let answers = self.fired.entry(key).or_default();
        match answers.iter_mut().find(|a| a.rule_id == rule_id) {
            Some(a) => a.acted |= acted,
            None => answers.push(Answer { rule_id, acted }),
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

    fn acted(rule_id: &'static str) -> Answer {
        Answer {
            rule_id,
            acted: true,
        }
    }

    fn recorded(rule_id: &'static str) -> Answer {
        Answer {
            rule_id,
            acted: false,
        }
    }

    const C001: &str = "NN-L-CHAIN-001_CredReadThenEgress";
    const C002: &str = "NN-L-CHAIN-002_TmpExecThenEgress";
    const C007: &str = "NN-L-CHAIN-007_TmpCredExfilSequence";
    const NET010: &str = "NN-L-NET-010_OutboundToHighRiskC2Port";

    #[test]
    fn a_rule_answers_a_flow_once_and_the_chains_once_between_them() {
        let fired = [acted(NET010)];
        assert!(excluded(NET010, &fired));
        assert!(!excluded("NN-L-NET-009_ByteAnomaly", &fired));
        assert!(!excluded(C001, &fired));
        let fired = [acted(C007)];
        assert!(excluded(C001, &fired));
        assert!(excluded(C002, &fired));
        assert!(!excluded("NN-L-NET-008_OutboundFromTmpExec", &fired));
        assert!(!excluded("anything", &[]));
    }

    /// Bug hunt 1.3, BUG45: a chain answer that was only a record keeps
    /// the chains judging the flow — the same chain included — and only a
    /// chain match that acts answers it again; any other rule answers a
    /// flow once, whatever its answer did.
    #[test]
    fn a_record_only_chain_answer_leaves_the_flow_to_a_chain_that_acts() {
        let fired = [recorded(C001)];
        for chain in [C001, C002, C007] {
            assert!(!excluded(chain, &fired), "{chain}");
            assert!(suppressed(chain, false, &fired), "{chain}: a record again");
            assert!(!suppressed(chain, true, &fired), "{chain}: one that acts");
        }
        let fired = [recorded(NET010), acted("NN-L-NET-008_OutboundFromTmpExec")];
        assert!(excluded(NET010, &fired));
        assert!(!suppressed(NET010, false, &fired));
        assert!(!suppressed(C001, false, &fired), "no chain answered");
        assert!(!suppressed(C001, false, &[]));
        // a chain that acted holds the flow against every chain
        let fired = [recorded(C001), acted(C002)];
        assert!(excluded(C001, &fired) && excluded(C007, &fired));
    }

    /// Lab PR 246: a trip's connection stays owned past its close (a row
    /// may follow the close from another task), the claim is bounded,
    /// oldest out, and it is the trip's connection only.
    #[test]
    fn a_trip_owns_its_connection_past_the_close_and_claims_are_bounded() {
        let mut l = FlowLedger::with_capacity(8);
        l.trips_cap = 2;
        l.record((9825, 100), "NN-L-NET-006_UncommonListener", false);
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
        l.record((1, 10), "A", false);
        l.record((1, 10), "A", true);
        l.record((1, 10), "B", true);
        l.record((1, 10), "B", false);
        assert_eq!(l.fired(&(1, 10)), Some(vec![acted("A"), acted("B")]));
        l.record((2, 20), "A", false);
        assert_eq!(l.fired(&(2, 20)), Some(vec![recorded("A")]));
        l.record((3, 30), "A", true);
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
