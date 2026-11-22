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

/// Lot 389 (F2h-1): the boots before this one as a list `v` (oldest first,
/// this boot last) gives them to the walk, one at a time — and what it was
/// asked, in order.
fn walk_of(
    v: Vec<String>,
    asked: &std::cell::RefCell<Vec<(String, usize)>>,
) -> impl FnMut(&str, usize) -> BootBefore + '_ {
    move |current, k| {
        asked.borrow_mut().push((current.to_string(), k));
        match v.len().checked_sub(k + 1) {
            Some(i) => BootBefore::Boot(v[i].clone()),
            None => BootBefore::NoSuchBoot,
        }
    }
}

/// systemd 249's `--list-boots`: the journal's boots from the oldest,
/// stopped at the first one met twice — 383 of rc14's 422, never this boot.
fn list_249(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("{:032x}", 0xd00d_0000_u64 + i as u64))
        .collect()
}

/// Lot 389 (F2h-1, rc14's ubuntu2204): the boot right before this one is
/// asked first, by this boot's id, and is the last run's — the next boot,
/// at the first question; the list (which on systemd 249 stops short of
/// this boot) is not asked.
#[test]
fn the_boot_right_before_this_one_being_the_last_runs_is_the_next_boot() {
    let asked = std::cell::RefCell::new(Vec::new());
    let got = judge_walking(
        facts(Some(A), Some(C)),
        walk_of(vec![j(D), j(A), j(C)], &asked),
        || panic!("the walk reached the last run's boot"),
    );
    assert_eq!(got, BootContinuity::NextBoot);
    assert_eq!(asked.into_inner(), vec![(j(C), 1)]);
}

/// Lot 389 (F2h-1): a boot without the agent (rc14's masked boot) found
/// walking back from this boot while the list stops 39 boots short of it:
/// `boots_without_agent`, counted and named, never `unknown`.
#[test]
fn a_boot_without_the_agent_is_found_walking_back_when_the_list_stops_short() {
    let asked = std::cell::RefCell::new(Vec::new());
    let got = judge_walking(
        facts(Some(A), Some(C)),
        walk_of(vec![j(A), j(B), j(C)], &asked),
        || Ok(list_249(383)),
    );
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: 1,
            boot_ids: vec![j(B)]
        }
    );
    assert_eq!(asked.into_inner(), vec![(j(C), 1), (j(C), 2)]);
    // the old rule on the same list: unknown — what rc14 signed at every start
    assert!(matches!(
        judge(facts(Some(A), Some(C)), || Ok(list_249(383))),
        BootContinuity::Unknown { .. }
    ));
}

/// Lot 389 (F2h-1): a walk that does not reach the last run's boot (the
/// journal ends, does not answer) leaves the judgement to the list — on
/// systemd 249's short list `unknown`, its why naming both answers; on a
/// list that reaches this boot, the list's judgement (a long gap counted
/// whole past the walk's bound).
#[test]
fn a_walk_that_does_not_reach_the_last_run_leaves_the_list_to_judge() {
    let asked = std::cell::RefCell::new(Vec::new());
    // a volatile journal: no boot before this one, and a short list
    let got = judge_walking(facts(Some(A), Some(C)), walk_of(vec![j(C)], &asked), || {
        Ok(list_249(383))
    });
    let BootContinuity::Unknown { why } = &got else {
        panic!("{got:?}")
    };
    assert!(why.contains("not in the journal's boot list (383"), "{why}");
    assert!(
        why.contains("named 0 boot(s)") && why.contains("no boot -1)"),
        "{why}"
    );
    assert_eq!(
        asked.borrow().len(),
        1,
        "a journal without the boot is not asked further"
    );
    // the journal does not answer: asked once, the list judges
    let mut n = 0;
    let got = judge_walking(
        facts(Some(A), Some(C)),
        |_: &str, _: usize| {
            n += 1;
            BootBefore::NoAnswer("killed past 2 s".into())
        },
        || Ok(vec![j(A), j(B), j(C)]),
    );
    assert_eq!(n, 1);
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: 1,
            boot_ids: vec![j(B)]
        }
    );
    // past the walk's bound: never asked further, the whole list counts
    let gap: Vec<String> = (0..WALK_MAX + 3)
        .map(|i| format!("{:032x}", i + 1))
        .collect();
    let mut list = vec![j(A)];
    list.extend(gap.iter().cloned());
    list.push(j(C));
    let asked = std::cell::RefCell::new(Vec::new());
    let got = judge_walking(
        facts(Some(A), Some(C)),
        walk_of(list.clone(), &asked),
        || Ok(list.clone()),
    );
    assert_eq!(asked.borrow().len(), WALK_MAX);
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: gap.len() as u64,
            boot_ids: gap[..LISTED_BOOT_IDS_MAX].to_vec()
        }
    );
}

/// Lot 389 (F2h-1): the journal's two answers disagree — the walk names
/// another boot right before this one, the list puts the last run's there:
/// `unknown`, never the clean "next boot".
#[test]
fn a_list_that_contradicts_the_walk_is_unknown_never_clean() {
    let asked = std::cell::RefCell::new(Vec::new());
    let mut walk = walk_of(vec![j(B), j(C)], &asked);
    let got = judge_walking(
        facts(Some(A), Some(C)),
        |c: &str, k: usize| match k {
            1 => walk(c, k),
            _ => BootBefore::NoAnswer("killed past 2 s".into()),
        },
        || Ok(vec![j(A), j(C)]),
    );
    let BootContinuity::Unknown { why } = &got else {
        panic!("{got:?}")
    };
    assert!(why.contains(&j(B)), "{why}");
    assert!(!got.continuous());
}

/// Lot 389 (F2h-1): the walk keeps lot 387's rules — a restart or a first
/// run asks nothing, an unreadable fact is unknown, the walk's ids are one
/// form, and a boot met twice (its entries split by another's) counts
/// once; this very boot named as a boot before it stops the walk.
#[test]
fn the_walk_keeps_the_list_rules() {
    let never_walk = |_: &str, _: usize| -> BootBefore { panic!("nothing asked") };
    assert_eq!(
        judge_walking(facts(Some(C), Some(C)), never_walk, never),
        BootContinuity::SameBoot
    );
    let first = BootFacts {
        previous_run: false,
        previous_boot: None,
        current_boot: Some(C),
    };
    assert_eq!(
        judge_walking(first, never_walk, never),
        BootContinuity::FirstRun
    );
    assert!(matches!(
        judge_walking(facts(None, Some(C)), never_walk, never),
        BootContinuity::Unknown { .. }
    ));
    assert!(matches!(
        judge_walking(facts(Some(A), None), never_walk, never),
        BootContinuity::Unknown { .. }
    ));
    // the kernel's form and capitals: one boot
    let got = judge_walking(
        facts(Some(A), Some(C)),
        |_: &str, k: usize| match k {
            1 => BootBefore::Boot(B.to_uppercase()),
            _ => BootBefore::Boot(A.into()),
        },
        never,
    );
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: 1,
            boot_ids: vec![j(B)]
        }
    );
    // a boot met twice before the last run's (its entries split by
    // another's): counted once
    let asked = std::cell::RefCell::new(Vec::new());
    let got = judge_walking(
        facts(Some(A), Some(C)),
        walk_of(vec![j(A), j(B), j(D), j(B), j(C)], &asked),
        never,
    );
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: 2,
            boot_ids: vec![j(B), j(D)]
        }
    );
    // this very boot named as a boot before it (systemd 255 ignoring the
    // offset of `-b <id>-<k>`, lot 389's lab): the walk stops, not counting
    // it, and the list judges — its next boot stands, no contradiction
    let asked = std::cell::RefCell::new(Vec::new());
    let got = judge_walking(
        facts(Some(A), Some(C)),
        |c: &str, k: usize| {
            asked.borrow_mut().push(k);
            BootBefore::Boot(c.to_string())
        },
        || Ok(vec![j(A), j(C)]),
    );
    assert_eq!(got, BootContinuity::NextBoot);
    assert_eq!(asked.into_inner(), vec![1]);
    // an answer that names no boot ends the walk; the list judges
    let got = judge_walking(
        facts(Some(A), Some(C)),
        |_: &str, _: usize| BootBefore::Boot("no id".into()),
        || Ok(vec![j(A), j(C)]),
    );
    assert!(matches!(got, BootContinuity::NextBoot), "{got:?}");
}

/// Lot 389 (F2h-1): the walk reaches the last run's boot past as many boots
/// without the agent as a row lists ([`LISTED_BOOT_IDS_MAX`]) — on systemd
/// 249, whose list stops short, the walk alone names them all.
#[test]
fn the_walk_reaches_past_every_boot_a_row_lists() {
    let gap: Vec<String> = (0..LISTED_BOOT_IDS_MAX)
        .map(|i| format!("{:032x}", i + 1))
        .collect();
    let mut list = vec![j(A)];
    list.extend(gap.iter().cloned());
    list.push(j(C));
    let asked = std::cell::RefCell::new(Vec::new());
    let got = judge_walking(facts(Some(A), Some(C)), walk_of(list, &asked), || {
        panic!("the walk reached the last run's boot: the list is not asked")
    });
    assert_eq!(
        got,
        BootContinuity::BootsWithoutAgent {
            count: LISTED_BOOT_IDS_MAX as u64,
            boot_ids: gap
        }
    );
    assert_eq!(asked.borrow().len(), LISTED_BOOT_IDS_MAX + 1);
}
