//! Lot 355: an exec's image is judged "staged" in one way, and this ratchet
//! keeps it so.
//!
//! An AppImage's runtime serves its image read-only at `/tmp/.mount_*`:
//! every program of a desktop user's AppImage was an exec from `/tmp` —
//! R001 High, CHAIN-002/005 Critical once it connected — though the same
//! program run from the home drew none. The exec pump marks such an exec
//! `exe_flags::USER_IMAGE` (`nn_linux::sensors::app_image`), and the
//! staging rules read it through one door:
//!
//! - an exec event: `rules::staging_judged_path` (the path the rules judge,
//!   `None` for a user's image) or `rules::is_staged_exec`;
//! - a process judged later by its image path (a flow, an ancestor):
//!   `AuthSessionTracker::staged_image_as` (the path, and the spawn cache's
//!   `user_image` for that process).
//!
//! A new site that tests an image against the staging directories by hand
//! — `is_staging_path` named, or a `starts_with("/tmp/")`,
//! `starts_with("/var/tmp/")`, `starts_with("/dev/shm/")` — fails here
//! until it goes through the door, or its file is listed in [`KNOWN`] with
//! its count and why it judges no exec's image by hand. The scan is
//! lexical over the product code (comments blanked, test items and test
//! files left out); the rule is shown failing on a planted site.

mod support;

use std::collections::BTreeMap;

use support::{product_code, repo_root};

/// The door: the helpers' own file.
const DOOR: &str = "crates/nn-core/src/decision/rules/mod.rs";

/// The tests by hand.
const MARKERS: &[&str] = &[
    "is_staging_path",
    "starts_with(\"/tmp/\")",
    "starts_with(\"/var/tmp/\")",
    "starts_with(\"/dev/shm/\")",
];

fn count(text: &str) -> usize {
    MARKERS.iter().map(|m| text.matches(m).count()).sum()
}

/// The files that hold sites: how many, and why.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-core/src/decision/rules/r001_exec_from_tmp.rs",
        1,
        "R001's own prefix, tested on the path `staging_judged_path` gave (a user's image \
         gives none)",
    ),
    (
        "crates/nn-core/src/decision/rules/r002_exec_from_dev_shm.rs",
        1,
        "R002's own prefix, tested on the path `staging_judged_path` gave (a user's image \
         gives none)",
    ),
    (
        "crates/nn-core/src/decision/rules/r003_exec_from_var_tmp.rs",
        1,
        "R003's own prefix, tested on the path `staging_judged_path` gave (a user's image \
         gives none)",
    ),
    (
        "crates/nn-core/src/posture/triggers.rs",
        2,
        "the exec arm's prefix test on the path `staging_judged_path` gave; and a device node \
         told from the `/dev/shm` filesystem's files (an open's path, no exec's image)",
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        1,
        "`staged_image_as` itself: the path, and the spawn cache's `user_image`",
    ),
    (
        "crates/nn-core/src/decision/rules/net.rs",
        2,
        "NN-L-NET-008 without a lineage (`staged_image_as` with one); and the pacing guard's \
         superset `may_meet_a_kill_rule` (a flow it lets through unthrottled: more, never fewer)",
    ),
    (
        "crates/nn-core/src/decision/rules/transfer_tools.rs",
        1,
        "a script an interpreter runs, by its argv's path (the script's file is not read: \
         stricter, a script of an image judged as staged)",
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        1,
        "a script an interpreter runs, by its argv's path (the script's file is not read: \
         stricter, a script of an image judged as staged)",
    ),
    (
        "crates/nn-core/src/fim/drift.rs",
        3,
        "a file written into a staging directory (the drift of a write), no exec's image",
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        2,
        "the exec pump's tie itself: an exec in a staging directory is the one it reads",
    ),
];

fn violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut out = Vec::new();
    for (file, text) in code {
        if file == DOOR {
            continue;
        }
        let n = count(text);
        match known.get(file.as_str()) {
            None if n > 0 => out.push(format!(
                "{file}: {n} staging test(s) by hand — judge an exec's image with \
                 `rules::staging_judged_path` / `rules::is_staged_exec`, a process's with \
                 `AuthSessionTracker::staged_image_as` (an AppImage's program is no staged \
                 image), or list the file in KNOWN with why"
            )),
            Some(&pin) if n > pin => out.push(format!("{file}: {n} sites, {pin} known: a new one")),
            Some(&pin) if n < pin => out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            )),
            _ => {}
        }
    }
    for (file, _, _) in KNOWN {
        if !code.contains_key(*file) {
            out.push(format!("{file}: listed in KNOWN, not in the scan"));
        }
    }
    out
}

/// No exec's image is judged staged outside the door.
#[test]
fn staged_images_are_judged_through_the_one_door() {
    let code = product_code(&repo_root());
    let door = code.get(DOOR).expect("the door is scanned");
    for helper in [
        "pub fn is_staging_path",
        "pub fn staging_judged_path",
        "pub fn is_staged_exec",
    ] {
        assert!(door.contains(helper), "{helper}");
    }
    assert!(
        door.contains("USER_IMAGE"),
        "the door reads the pump's mark"
    );
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// A planted site fails; a listed file over its pin fails.
#[test]
fn a_staging_test_by_hand_fails_the_ratchet() {
    let mut code = product_code(&repo_root());
    code.insert(
        format!("{}/r099_planted.rs", "crates/nn-core/src/decision/rules"),
        "fn evaluate(e: &Event) { if exe.path_or(f).starts_with(\"/tmp/\") {} }".into(),
    );
    let r001 = "crates/nn-core/src/decision/rules/r001_exec_from_tmp.rs";
    let more = format!("{} is_staging_path(x)", code[r001]);
    code.insert(r001.into(), more);
    let v = violations(&code);
    assert!(v.iter().any(|m| m.contains("r099_planted")), "{v:#?}");
    assert!(
        v.iter()
            .any(|m| m.contains("r001_exec_from_tmp") && m.contains("a new one")),
        "{v:#?}"
    );
}
