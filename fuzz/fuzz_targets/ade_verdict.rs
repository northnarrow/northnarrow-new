#![no_main]
//! ADE model output (WDG-R04, NN-AUD-370): the model's text is shaped by
//! the event it reads (file names, command lines), so by whoever wrote
//! them. The parser is the gate between that text and a response. Beyond
//! "never panics", a verdict it accepts:
//! - meets the schema rules a response relies on, checked here apart from
//!   `validate`: confidence and novelty in [0, 1] (LLMP-006: a Kill at
//!   5.00 cleared every threshold), below 0.40 only Escalate, Isolate only
//!   at 0.85 and Critical, Allow exactly with severity None, Escalate
//!   exactly with a tier and a package, a UUID v4 trace id;
//! - parses again from its own JSON, alone and inside code fences, to the
//!   same decision. (A JSON that carries `<think>` is left out until the
//!   pre-parser stops matching the marker inside the object: NN-AUD-380,
//!   batch 6 of the Wave 3 triage.)
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::ade::parser::VerdictParser;
use northnarrow_common::ade_types::{AdeAction, AdeSeverity, AdeVerdict};

fn decision(v: &AdeVerdict) -> (AdeAction, AdeSeverity, u64, String) {
    (
        v.verdict,
        v.severity,
        v.confidence.to_bits(),
        v.trace_id.clone(),
    )
}

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let parser = VerdictParser::new();
    let Ok(v) = parser.parse(&raw) else {
        return;
    };
    assert!((0.0..=1.0).contains(&v.confidence), "{}", v.confidence);
    assert!((0.0..=1.0).contains(&v.threat_classification.novelty));
    if v.confidence < 0.40 {
        assert_eq!(v.verdict, AdeAction::Escalate);
    }
    if v.verdict == AdeAction::Isolate {
        assert!(v.confidence >= 0.85 && v.severity == AdeSeverity::Critical);
    }
    assert_eq!(
        v.verdict == AdeAction::Allow,
        v.severity == AdeSeverity::None
    );
    let packaged = v.escalation_tier.is_some() && v.escalation_package.is_some();
    let bare = v.escalation_tier.is_none() && v.escalation_package.is_none();
    assert!(if v.verdict == AdeAction::Escalate {
        packaged
    } else {
        bare
    });
    let id = v.trace_id.as_bytes();
    assert!(id.len() == 36 && id[14] == b'4' && matches!(id[19], b'8' | b'9' | b'a' | b'b'));
    assert!(parser.validate(&v).is_ok());

    let json = serde_json::to_string(&v).expect("a verdict serialises");
    if json.contains("<think>") {
        return;
    }
    for text in [json.clone(), format!("```json\n{json}\n```")] {
        let again = parser
            .parse(&text)
            .expect("an accepted verdict parses from its own JSON");
        assert_eq!(decision(&again), decision(&v));
    }
});
