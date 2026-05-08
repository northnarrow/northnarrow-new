//! Tappa 5 demo rules — `R901..=R904`.
//!
//! These exist ONLY to give the manual demo a deterministic way to
//! trigger each new ResponseAction. They are gated behind the
//! `demo-tappa5` feature and never enter `default_rules()`. Build a
//! production binary without the feature and they simply don't
//! exist.
//!
//! Trigger surface is filename-suffix matching on
//! `Event::ProcessSpawn`. Pick a suffix that's clearly a test
//! payload (`*.block-outbound`, `*.isolate-network`,
//! `*.quarantine-me`, `*.throttle-me`).

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

pub struct R901TestBlockOutbound;
pub struct R902TestNetworkIsolation;
pub struct R903TestQuarantine;
pub struct R904TestThrottle;

fn matches_suffix(event: &Event, suffix: &str) -> bool {
    matches!(
        event,
        Event::ProcessSpawn { filename, .. } if filename.ends_with(suffix)
    )
}

impl Rule for R901TestBlockOutbound {
    fn id(&self) -> &'static str {
        "R901_TestBlockOutbound"
    }
    fn name(&self) -> &'static str {
        "DEMO: Block outbound traffic"
    }
    fn category(&self) -> &'static str {
        "demo_tappa5"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if !matches_suffix(event, ".block-outbound") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::BlockOutbound,
            Severity::High,
            "DEMO Tappa 5 — block outbound traffic from the target PID",
        ))
    }
}

impl Rule for R902TestNetworkIsolation {
    fn id(&self) -> &'static str {
        "R902_TestNetworkIsolation"
    }
    fn name(&self) -> &'static str {
        "DEMO: Engage full network isolation"
    }
    fn category(&self) -> &'static str {
        "demo_tappa5"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if !matches_suffix(event, ".isolate-network") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::FullNetworkIsolation,
            Severity::Critical,
            "DEMO Tappa 5 — engage host-wide network isolation",
        ))
    }
}

impl Rule for R903TestQuarantine {
    fn id(&self) -> &'static str {
        "R903_TestQuarantine"
    }
    fn name(&self) -> &'static str {
        "DEMO: Quarantine binary"
    }
    fn category(&self) -> &'static str {
        "demo_tappa5"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if !matches_suffix(event, ".quarantine-me") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Quarantine,
            Severity::High,
            "DEMO Tappa 5 — quarantine the target's binary",
        ))
    }
}

impl Rule for R904TestThrottle {
    fn id(&self) -> &'static str {
        "R904_TestThrottle"
    }
    fn name(&self) -> &'static str {
        "DEMO: Throttle process"
    }
    fn category(&self) -> &'static str {
        "demo_tappa5"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if !matches_suffix(event, ".throttle-me") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::ThrottleProcess,
            Severity::Medium,
            "DEMO Tappa 5 — throttle the target's CPU + IO",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn r901_fires_on_block_outbound_suffix() {
        let v = R901TestBlockOutbound
            .evaluate(&spawn("payload", "/tmp/x.block-outbound"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::BlockOutbound);
    }

    #[test]
    fn r902_fires_on_isolate_network_suffix() {
        let v = R902TestNetworkIsolation
            .evaluate(&spawn("payload", "/tmp/x.isolate-network"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::FullNetworkIsolation);
    }

    #[test]
    fn r903_fires_on_quarantine_me_suffix() {
        let v = R903TestQuarantine
            .evaluate(&spawn("payload", "/tmp/x.quarantine-me"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Quarantine);
    }

    #[test]
    fn r904_fires_on_throttle_me_suffix() {
        let v = R904TestThrottle
            .evaluate(&spawn("payload", "/tmp/x.throttle-me"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::ThrottleProcess);
    }

    #[test]
    fn demo_rules_ignore_unrelated_events() {
        let evt = spawn("ls", "/usr/bin/ls");
        assert!(R901TestBlockOutbound.evaluate(&evt).is_none());
        assert!(R902TestNetworkIsolation.evaluate(&evt).is_none());
        assert!(R903TestQuarantine.evaluate(&evt).is_none());
        assert!(R904TestThrottle.evaluate(&evt).is_none());
    }
}
