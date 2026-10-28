//! The exploit guard's `off` is a weakening the agent reports (lab PR 219).
//! Wave 4 restructure, R09b (lab PR 254): cut verbatim from the tests of
//! `sensors::epg`, which leaves for nn-linux; the list it reads is the
//! agent's (`self_integrity::WEAKENING_ENV`), so it stays with it.

use crate::sensors::epg::MODE_ENV;

/// `NN_EXPLOIT_GUARD=off` is reported as a weakening (signed
/// `integrity_drift`); `lite` and `strict` are not.
#[test]
fn the_off_value_is_a_weakening_variable() {
    assert!(crate::self_integrity::WEAKENING_ENV
        .iter()
        .any(|(name, weakens)| *name == MODE_ENV
            && weakens("off")
            && !weakens("lite")
            && !weakens("strict")));
}
