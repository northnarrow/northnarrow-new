//! Lot 273c/273d: the host's drop-ins judged by their value for our units.
//! The judge lives in `antitamper_bpf::host_dropins` (the watchdog reads it
//! before a respawn); the agent's side is here: what it holds is a
//! degradation while it holds.

pub use antitamper_bpf::host_dropins::*;

/// The degradation's source (`nn-admin status --key`, the manifest, the
/// heartbeat, the warning at a window's grant).
pub const DEGRADATION: &str = "host_dropins";

/// The warning a harmful host drop-in carries: what the lab's round 7 of
/// lot 273c measured.
pub const WINDOW_WARNING: &str = "a daemon-reload inside a trusted-installer window applies it \
     to our units: the agent, the watchdog and journald die (remove it first)";

/// Lot 273d (the review of #492): each harmful host drop-in (`harms`, the
/// round's or a window's grant's) is a degradation while it is on disk —
/// visible in `nn-admin status --key`, the capability manifest and the
/// heartbeat, so that a false positive, which withholds the agent's
/// reloads, is seen too — and the ones no longer there are withdrawn.
pub fn note_degradation(harms: &[Harm]) {
    let lines: Vec<String> = harms
        .iter()
        .filter(|h| h.kind == Kind::Harmful)
        .map(|h| format!("{} — {WINDOW_WARNING}", h.detail()))
        .collect();
    crate::boot::degradation::withdraw(DEGRADATION, &lines);
    for l in &lines {
        crate::boot::degradation::report(DEGRADATION, l);
    }
}

/// The re-check of #582 (N0): the degradation's source when systemd's copy
/// of one of our units does not deny memory both writable and executable
/// (`MemoryDenyWriteExecute=`), whatever spelling turned it off.
pub const MDWE_DEGRADATION: &str = "units_mdwe";

/// The re-check of #582 (N0): our units' `MemoryDenyWriteExecute` as
/// systemd holds it (its copy, which the units' starts apply) — off, or not
/// read, is a degradation of this start (signed at the log's open). Nothing
/// for a start that is not its unit's (a hand-run binary) or on a host
/// without systemd's private socket. Blocking (2 s at most each exchange):
/// at the start, before the runtime.
pub fn note_units_mdwe() {
    use antitamper_bpf::systemd_bus::{unit_property, Value, PRIVATE_SOCKET};
    let socket = std::path::Path::new(PRIVATE_SOCKET);
    if !socket.exists()
        || !antitamper_bpf::start_check::identity(std::process::id())
            .in_unit(antitamper_bpf::start_check::AGENT_UNIT)
    {
        return;
    }
    for unit in [
        antitamper_bpf::start_check::AGENT_UNIT,
        antitamper_bpf::start_check::WATCHDOG_UNIT,
    ] {
        let line = match unit_property(
            socket,
            std::time::Duration::from_secs(2),
            unit,
            antitamper_bpf::unit_props::SERVICE,
            "MemoryDenyWriteExecute",
        ) {
            Ok(Value::Bool(true)) => continue,
            Ok(v) => mdwe_line(unit, &format!("{v:?}")),
            Err(e) => mdwe_line(unit, &format!("not read ({e})")),
        };
        crate::boot::degradation::report(MDWE_DEGRADATION, &line);
    }
}

/// The degradation's line for `unit` whose copy says `value`.
pub fn mdwe_line(unit: &str, value: &str) -> String {
    format!(
        "systemd's copy of {unit}: MemoryDenyWriteExecute {value}, not on — code no file backs \
         could run in its starts"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_harmful_drop_in_is_a_degradation_while_it_holds() {
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        crate::boot::degradation::reset_for_tests();
        let harm = |kind| Harm {
            path: "/etc/systemd/system/system.slice.d/99-x.conf".into(),
            directive: "MemoryMax".into(),
            value: "4K".into(),
            why: "below the slice's floor".into(),
            reach: Reach::OurSlice,
            kind,
        };
        note_degradation(&[harm(Kind::Harmful), harm(Kind::BreaksAgent)]);
        let s = crate::boot::degradation::snapshot();
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(s[0].starts_with(
            "host_dropins: /etc/systemd/system/system.slice.d/99-x.conf sets MemoryMax=4K"
        ));
        assert!(s[0].contains("the agent, the watchdog and journald die"));
        note_degradation(&[]);
        assert!(crate::boot::degradation::snapshot().is_empty());
        crate::boot::degradation::reset_for_tests();
    }
}
