use super::*;

const A: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
const B: &str = "1111aaaa-2222-3333-4444-555566667777";
const C: &str = "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0";
const D: &str = "abcdefab-cdef-abcd-efab-cdefabcdefab";

fn j(id: &str) -> String {
    normalize(id).unwrap()
}

fn facts<'a>(previous: Option<&'a str>, current: Option<&'a str>) -> BootFacts<'a> {
    BootFacts {
        previous_run: true,
        previous_boot: previous,
        current_boot: current,
    }
}

fn never() -> Result<Vec<String>, String> {
    panic!("the journal must not be asked within the same boot")
}

/// F3d-1 (B5, B9): a boot listed between the last run's and this one is a
/// boot without the agent — never `clean`.
#[test]
fn a_boot_between_the_last_run_and_this_start_is_a_boot_without_the_agent() {
    let got = judge(facts(Some(A), Some(C)), || Ok(vec![j(A), j(B), j(C)]));
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: 1,
            boot_ids: vec![j(B)]
        }
    );
    assert!(!got.continuous());
    assert_eq!(got.label(), BOOTS_WITHOUT_AGENT_KIND);
    let two = judge(facts(Some(A), Some(C)), || {
        Ok(vec![j(D), j(A), j(B), j(D), j(C)])
    });
    assert_eq!(
        two,
        BootContinuity::BootsWithoutAgent {
            count: 2,
            boot_ids: vec![j(B), j(D)]
        }
    );
}

/// A boot listed twice (its entries split by another boot's): the window is
/// the widest — from the first listing of the last run's boot to the last
/// listing of this one — and each boot in it is counted once, neither end.
#[test]
fn boots_listed_twice_widen_the_window_and_count_once() {
    let gap = |list: Vec<String>| judge(facts(Some(A), Some(C)), || Ok(list));
    let b = |ids: &[&str]| BootContinuity::BootsWithoutAgent {
        count: ids.len() as u64,
        boot_ids: ids.iter().map(|i| j(i)).collect(),
    };
    // the last run's boot listed again after a boot without the agent
    assert_eq!(gap(vec![j(A), j(B), j(A), j(C)]), b(&[B]));
    // this boot listed before and after one
    assert_eq!(gap(vec![j(A), j(C), j(B), j(C)]), b(&[B]));
    // one boot listed twice in the window
    assert_eq!(gap(vec![j(A), j(B), j(D), j(B), j(C)]), b(&[B, D]));
    // the list in the kernel's form, or in capitals: the same boots
    assert_eq!(gap(vec![A.into(), B.to_uppercase(), C.into()]), b(&[B]));
}

/// A normal reboot: the next boot in the list, no gap.
#[test]
fn the_next_boot_in_the_list_is_no_gap() {
    let got = judge(facts(Some(A), Some(B)), || Ok(vec![j(D), j(A), j(B)]));
    assert_eq!(got, BootContinuity::NextBoot);
    assert!(got.continuous());
}

/// A restart (a maintenance stop and start): the same boot, and the
/// journal is not even asked.
#[test]
fn a_restart_in_the_same_boot_is_no_gap_and_asks_no_journal() {
    assert_eq!(
        judge(facts(Some(A), Some(A)), never),
        BootContinuity::SameBoot
    );
    // the kernel's form and the journal's are one boot
    assert_eq!(
        judge(facts(Some(&j(A)), Some(&A.to_uppercase())), never),
        BootContinuity::SameBoot
    );
}

#[test]
fn a_first_run_has_nothing_to_judge() {
    let f = BootFacts {
        previous_run: false,
        previous_boot: None,
        current_boot: Some(A),
    };
    assert_eq!(judge(f, never), BootContinuity::FirstRun);
    assert!(BootContinuity::FirstRun.continuous());
}

/// F3d-1: a volatile journal keeps only this boot — the boots in between
/// are not knowable: `unknown`, never `clean`.
#[test]
fn a_journal_that_lost_the_last_runs_boot_is_unknown_never_clean() {
    let got = judge(facts(Some(A), Some(C)), || Ok(vec![j(C)]));
    match &got {
        BootContinuity::Unknown { why } => {
            assert!(why.contains("volatile"), "{why}");
            assert!(why.contains("1 boot(s) kept"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    assert!(!got.continuous());
}

/// One case: the facts, the journal's answer, a word of the `why`.
type Case<'a> = (BootFacts<'a>, Result<Vec<String>, String>, &'a str);

/// Every fact that cannot be read is `unknown`, never a continuous state.
#[test]
fn every_unreadable_fact_is_unknown() {
    let cases: Vec<Case<'_>> = vec![
        (facts(Some(A), None), Ok(vec![]), "this boot's id"),
        (
            facts(Some(A), Some("not-a-boot-id")),
            Ok(vec![]),
            "this boot's id",
        ),
        (facts(None, Some(C)), Ok(vec![]), "not recorded"),
        (facts(Some("zz"), Some(C)), Ok(vec![]), "not recorded"),
        (
            facts(Some(A), Some(C)),
            Err("timed out".into()),
            "could not be read: timed out",
        ),
        (
            facts(Some(A), Some(C)),
            Ok(vec![j(A), j(B)]),
            "this boot is not in",
        ),
        (
            facts(Some(A), Some(C)),
            Ok(vec![]),
            "this boot is not in the journal's boot list (0 boot(s)",
        ),
        (
            facts(Some(A), Some(C)),
            Ok(vec![j(C), j(A)]),
            "the last run's boot",
        ),
        (
            facts(Some(A), Some(C)),
            Ok(vec![j(A), j(C), j(B)]),
            "lists 1 boot(s) after this one",
        ),
    ];
    for (f, list, want) in cases {
        let got = judge(f, move || list);
        match &got {
            BootContinuity::Unknown { why } => assert!(why.contains(want), "{why} / {want}"),
            other => panic!("{other:?}, wanted unknown with {want}"),
        }
        assert!(!got.continuous());
    }
}

/// Past [`LISTED_BOOT_IDS_MAX`], the ids are cut and the count is whole.
#[test]
fn many_boots_without_the_agent_are_counted_whole_and_listed_cut() {
    let mut list = vec![j(A)];
    for i in 0..20u32 {
        list.push(format!("{i:032x}"));
    }
    list.push(j(C));
    let got = judge(facts(Some(A), Some(C)), || Ok(list));
    match got {
        BootContinuity::BootsWithoutAgent { count, boot_ids } => {
            assert_eq!(count, 20);
            assert_eq!(boot_ids.len(), LISTED_BOOT_IDS_MAX);
            assert_eq!(boot_ids[0], format!("{:032x}", 0));
        }
        other => panic!("{other:?}"),
    }
}

/// The list's text, header and all, systemd 249 and 255 alike.
#[test]
fn the_journals_boot_list_is_parsed_in_its_order() {
    let v255 = "IDX BOOT ID                          FIRST ENTRY                 LAST ENTRY\n \
                -2 0f1e2d3c4b5a69788796a5b4c3d2e1f0 Sat 2026-11-21 08:00:01 UTC Sat 2026-11-21 09:00:00 UTC\n \
                -1 1111aaaa222233334444555566667777 Sat 2026-11-21 09:01:00 UTC Sat 2026-11-21 09:05:00 UTC\n  \
                0 9F8E7D6C5B4A39281706F5E4D3C2B1A0 Sat 2026-11-21 09:06:00 UTC Sat 2026-11-21 10:00:00 UTC\n";
    assert_eq!(parse_list_boots(v255), vec![j(A), j(B), j(C)]);
    let v249 = "-1 0f1e2d3c4b5a69788796a5b4c3d2e1f0 Sat 2026-11-21 08:00:01 UTC—Sat 2026-11-21 09:00:00 UTC\n \
                 0 9f8e7d6c5b4a39281706f5e4d3c2b1a0 Sat 2026-11-21 09:06:00 UTC—Sat 2026-11-21 10:00:00 UTC";
    assert_eq!(parse_list_boots(v249), vec![j(A), j(C)]);
    assert!(
        parse_list_boots("No journal boot entry found from the specified boot offset.\n")
            .is_empty()
    );
    assert!(parse_list_boots("").is_empty());
}

#[test]
fn boot_ids_are_one_form() {
    assert_eq!(normalize(A).unwrap(), "0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    assert_eq!(
        normalize(" 0F1E2D3C4B5A69788796A5B4C3D2E1F0\n").unwrap(),
        j(A)
    );
    assert_eq!(normalize("0f1e2d3c"), None);
    assert_eq!(normalize(&format!("{}0", j(A))), None);
    assert_eq!(normalize("zf1e2d3c4b5a69788796a5b4c3d2e1f0"), None);
}

/// What the rows sign: the state, and the count, ids or why.
#[test]
fn the_judgement_signs_its_state_and_facts() {
    assert_eq!(BootContinuity::SameBoot.to_json()["state"], "same_boot");
    assert_eq!(BootContinuity::NextBoot.to_json()["state"], "next_boot");
    assert_eq!(BootContinuity::FirstRun.to_json()["state"], "first_run");
    let gap = BootContinuity::BootsWithoutAgent {
        count: 3,
        boot_ids: vec![j(B)],
    }
    .to_json();
    assert_eq!(gap["state"], "boots_without_agent");
    assert_eq!(gap["count"], 3);
    assert_eq!(gap["boot_ids"][0], j(B));
    let unknown = BootContinuity::Unknown { why: "w".into() }.to_json();
    assert_eq!(unknown["state"], "unknown");
    assert_eq!(unknown["why"], "w");
    let s = sources_json();
    assert_eq!(s.as_array().unwrap().len(), SOURCES.len());
    assert!(s[2]["rewritable"].as_str().unwrap().contains("volatile"));
}
