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

use std::collections::HashMap;

use nn_model::telemetry::{FlowPhase, NetFlowEvent};
use nn_model::Verdict;

use super::bounded::LazyLru;

/// Flows with a verdict remembered at once.
pub const FLOW_LEDGER_CAP: usize = 16_384;

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
        }
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
