//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 4: the agent loads a single eBPF object exposing six
//! programs (process exec, file open, exec validation, TCP v4/v6
//! connect, UDP/DNS) via
//! [`SensorMultiplexer`](northnarrow_agent::sensors::SensorMultiplexer).
//!
//! Each event cascades through:
//!
//!   sensor → posture.observe → rule_engine → (match? execute)
//!
//! Sub-tappa 6.5: every event is also fed to the
//! [`PostureMachine`](northnarrow_agent::posture::PostureMachine), a
//! 4-tier defensive posture that persists across events and drives the
//! COMBAT ladder.
//!
//! Detection is deterministic. The on-host LLM advisor of Tappa 6 (the
//! ADE, which judged the execs no rule matched) was removed in Wave 4
//! (lab PR 214); its flags are accepted and ignored with a WARN
//! ([`northnarrow_agent::removed_settings`]).
//!
//! Wave 4 restructure, R11a (lab PR 261): the start's code is the
//! library's, in typed phases (`northnarrow_agent::boot`), the event
//! pipeline (`pipeline`), the event loop (`run_loop`) and the stop
//! (`shutdown`); this binary runs it.

fn main() -> anyhow::Result<()> {
    northnarrow_agent::boot::main()
}
