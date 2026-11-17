//! The review of #562 (lot 354, P3): the admin protocol's history is
//! append-only. `crates/nn-proto`'s `a_pinned_frame_changes_only_with_a_new_protocol_version`
//! ties the frames its tests pin to `PROTOCOL_VERSION` through
//! `PINNED_FRAMES_AT_VERSION`, one digest per version; but an edit of the
//! last row in place (the new frames' digest written over the old one, the
//! version left as it is) passed it. This copy of the rows sits in another
//! crate: a row of the table that changes, or a row added without its copy
//! here, fails this test. Raising the version means appending one row in
//! both places.

use std::fs;

mod support;

use support::repo_root;

/// Every row of `PINNED_FRAMES_AT_VERSION`, as it was recorded. Never edit
/// a row: a version's frames are history. Append a row when
/// `PROTOCOL_VERSION` moves.
const HISTORY: [(u16, &str); 4] = [
    (
        1,
        "e9acc80ae2d89bd2a65f21b5a336c6e1ca2bd3edde7c43006a322b112e6f35f3",
    ),
    (
        2,
        "c503c86c903c2fa3257d9c1a318aa3fcb885b04a5b345ca325b992dff2fcadfb",
    ),
    (
        3,
        "9cf9c1dabab1d292d83d0c69661faf81ce3cb582d21044b0cc1e314ce4e29739",
    ),
    (
        4,
        "a8f06c633972b30f52b3d8e85cbcb1a7965f5f1c55ec06b79e958bc3da96f879",
    ),
];

const SOURCE: &str = "crates/nn-proto/src/admin_protocol.rs";

/// The rows of `PINNED_FRAMES_AT_VERSION` in `text`: each `(version,
/// "digest")` between the table's `= [` and its `];`.
fn rows(text: &str) -> Vec<(u16, String)> {
    let start = text
        .find("const PINNED_FRAMES_AT_VERSION")
        .unwrap_or_else(|| panic!("{SOURCE}: no PINNED_FRAMES_AT_VERSION"));
    let body = &text[start..];
    let open = body.find("= [").expect("the table's `= [`") + 3;
    let close = body[open..].find("];").expect("the table's `];`") + open;
    let cells: Vec<String> = body[open..close]
        .split(['(', ')', ',', '\n', ' '])
        .map(|c| c.trim().trim_matches('"').to_string())
        .filter(|c| !c.is_empty())
        .collect();
    assert!(
        cells.len().is_multiple_of(2),
        "{SOURCE}: rows of two cells: {cells:?}"
    );
    cells
        .chunks(2)
        .map(|c| {
            let v: u16 = c[0]
                .parse()
                .unwrap_or_else(|_| panic!("{SOURCE}: a version {:?}", c[0]));
            assert!(
                c[1].len() == 64 && c[1].bytes().all(|b| b.is_ascii_hexdigit()),
                "{SOURCE}: a digest {:?}",
                c[1]
            );
            (v, c[1].clone())
        })
        .collect()
}

/// The table holds exactly the recorded history: no row edited, none
/// removed, none added without its copy here.
#[test]
fn the_protocol_history_is_append_only() {
    let text = fs::read_to_string(repo_root().join(SOURCE)).expect("admin_protocol.rs");
    let now = rows(&text);
    let want: Vec<(u16, String)> = HISTORY.iter().map(|(v, d)| (*v, d.to_string())).collect();
    for (i, (v, d)) in want.iter().enumerate() {
        match now.get(i) {
            Some((nv, nd)) if nv == v && nd == d => {}
            Some((nv, nd)) => panic!(
                "{SOURCE}: PINNED_FRAMES_AT_VERSION's row for version {v} is now ({nv}, {nd}): \
                 a version's frames are history. Leave the row as it was, raise \
                 PROTOCOL_VERSION and append a row (here too)"
            ),
            None => panic!("{SOURCE}: PINNED_FRAMES_AT_VERSION lost its row for version {v}"),
        }
    }
    assert_eq!(
        now.len(),
        want.len(),
        "{SOURCE}: a row appended to PINNED_FRAMES_AT_VERSION ({:?}): append it to \
         xtask/tests/protocol_history.rs's HISTORY too",
        &now[want.len().min(now.len())..]
    );
    let version = text
        .lines()
        .find_map(|l| l.strip_prefix("pub const PROTOCOL_VERSION: u16 = "))
        .and_then(|v| v.trim_end_matches(';').parse::<u16>().ok())
        .expect("PROTOCOL_VERSION");
    assert_eq!(
        Some(version),
        want.last().map(|(v, _)| *v),
        "PROTOCOL_VERSION is not the last version recorded"
    );
}

/// The parser sees an edited row, a removed one and an added one.
#[test]
fn the_history_check_sees_an_edit_in_place() {
    let text = fs::read_to_string(repo_root().join(SOURCE)).expect("admin_protocol.rs");
    let last = HISTORY[HISTORY.len() - 1].1;
    assert!(text.contains(last));
    let edited = text.replacen(last, &"0".repeat(64), 1);
    assert_ne!(rows(&edited), rows(&text));
    assert_eq!(rows(&edited).len(), HISTORY.len());
    assert_eq!(rows(&edited)[HISTORY.len() - 1].1, "0".repeat(64));
}
