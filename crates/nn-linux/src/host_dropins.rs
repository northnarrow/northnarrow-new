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
