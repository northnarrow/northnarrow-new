#![no_main]
//! The shutdown marker (WDG-014, NN-AUD-363): the file the agent leaves in
//! /run/northnarrow when an admin quorum authorised its shutdown, and the
//! watchdog reads to stand down instead of respawning it. Root can write
//! that directory, so the content is hostile. The check runs against a
//! fixed fixture (`fuzz_api`: three admin keys, one with `shutdown`, an
//! install, the agent's pid and start, the watchdog's clock). Beyond
//! "never panics", a marker the watchdog honours:
//! - carries a shutdown the fixture keys signed (the committed seed): the
//!   fuzzer cannot sign, so anything else honoured is a forgery accepted;
//! - names the agent that exited, carries at most the cap of signatures
//!   (AUT-005), has two distinct signers, the `shutdown` key among them,
//!   and a grace of at most `MAX_GRACE_SECS`;
//! - is refused as a replay once its nonce was honoured.
//!
//! A payload nested past ciborium's recursion limit is refused, not a
//! stack overflow (AUT-011, declined on that premise:
//! `fuzz/regressions/shutdown_marker/nested-cbor-payload.json`).
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::fuzz_api::{
    shutdown_marker_check, SHUTDOWN_FIXTURE_PID, SHUTDOWN_FIXTURE_SIGNED,
};
use northnarrow_common::admin_quorum::MAX_SUBMITTED_SIGNATURES;
use northnarrow_common::shutdown_marker::{Rejection, MAX_GRACE_SECS};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let Ok((marker, ok)) = shutdown_marker_check(raw, false) else {
        return;
    };
    assert!(
        SHUTDOWN_FIXTURE_SIGNED.iter().any(|(n, ts, g)| (
            *n,
            *ts,
            u64::from(*g).min(MAX_GRACE_SECS)
        ) == (ok.nonce, ok.ts, ok.grace_secs)),
        "honoured a shutdown no fixture key signed: {ok:?}"
    );
    assert_eq!(marker.agent_pid, SHUTDOWN_FIXTURE_PID);
    assert!(marker.signatures.len() <= MAX_SUBMITTED_SIGNATURES);
    assert!(
        ok.signers.len() >= 2 && ok.signers.contains(&0),
        "{:?}",
        ok.signers
    );
    assert!(ok.grace_secs <= MAX_GRACE_SECS);
    assert_eq!(
        shutdown_marker_check(raw, true).map(|_| ()),
        Err(Rejection::Replayed)
    );
});
