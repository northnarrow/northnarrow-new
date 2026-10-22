#![no_main]
//! Lab PR 236: `rule-policy.local`, the signed per-rule response policy.
//! Beyond "never panics": an accepted policy names only rules the engine
//! decides (each by its full id), never exempts uid 0, an executable
//! outside a root-owned system tree, a cgroup without a unit, or anything
//! by name (`comm`, `name`, `process`, `argv` refuse the file); at most
//! 64 exemptions per rule; its rendering parses back to the same policy.
//! A refusal names a line of the text.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::decision::rule_policy::{
    parse, resolve_rule, Exemption, MAX_EXEMPTIONS_PER_RULE,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match parse(text) {
        Ok(p) => {
            for (rule, _) in p.modes() {
                assert_eq!(resolve_rule(rule), Ok(rule), "{rule}");
            }
            for (rule, ex) in p.all_exemptions() {
                assert_eq!(resolve_rule(rule), Ok(rule), "{rule}");
                assert!(ex.len() <= MAX_EXEMPTIONS_PER_RULE);
                for e in ex {
                    match e {
                        Exemption::Uid(u) => assert!(*u != 0 && *u != u32::MAX),
                        Exemption::Exe { path, .. } => {
                            assert!(path.starts_with('/') && !path.contains("/../"), "{path}")
                        }
                        Exemption::Cgroup(c) => assert!(
                            c.ends_with(".service") || c.ends_with(".scope"),
                            "{c}"
                        ),
                        Exemption::Unit(u) => assert!(
                            u.ends_with(".service") || u.ends_with(".scope"),
                            "{u}"
                        ),
                    }
                }
            }
            for line in text.lines() {
                let content = line.split('#').next().unwrap_or("");
                let w: Vec<&str> = content.split_whitespace().collect();
                if w.first() == Some(&"exempt") {
                    assert!(
                        !matches!(w.get(2), Some(&("comm" | "name" | "process" | "argv"))),
                        "an exemption by name accepted: {line:?}"
                    );
                }
            }
            assert_eq!(parse(&p.render()).as_ref(), Ok(&p));
        }
        Err(e) => {
            assert!(e.line >= 1 && e.line <= text.lines().count().max(1), "{e}");
        }
    }
});
