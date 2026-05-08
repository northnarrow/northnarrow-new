//! R007 — Cryptocurrency miner detected by comm substring.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

const MINER_NEEDLES: &[&str] = &[
    "xmrig",
    "cpuminer",
    "minerd",
    "ccminer",
    "ethminer",
    "phoenixminer",
];

pub struct R007CryptoMiner;

impl Rule for R007CryptoMiner {
    fn id(&self) -> &'static str {
        "R007_CryptoMiner"
    }
    fn name(&self) -> &'static str {
        "Crypto miner"
    }
    fn category(&self) -> &'static str {
        "resource_abuse"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, .. } = event else {
            return None;
        };
        let comm_lc = comm.to_ascii_lowercase();
        if !MINER_NEEDLES.iter().any(|n| comm_lc.contains(n)) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "Cryptocurrency miner detected",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_known_miner_comms() {
        for n in MINER_NEEDLES {
            assert!(R007CryptoMiner
                .evaluate(&spawn(n, "/tmp/whatever"))
                .is_some());
        }
        // Substring match: an obfuscated comm still trips us.
        assert!(R007CryptoMiner
            .evaluate(&spawn("kthreadd_xmrig", "/tmp/x"))
            .is_some());
    }

    #[test]
    fn ignores_unrelated_comms() {
        assert!(R007CryptoMiner
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn match_is_case_insensitive() {
        assert!(R007CryptoMiner
            .evaluate(&spawn("XMRig", "/opt/XMRig"))
            .is_some());
        let v = R007CryptoMiner
            .evaluate(&spawn("XMRig", "/opt/XMRig"))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.severity, Severity::Critical);
    }
}
