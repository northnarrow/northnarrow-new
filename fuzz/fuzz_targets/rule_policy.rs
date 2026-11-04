#![no_main]
//! Lab PR 236: `rule-policy.local`, the signed per-rule response policy.
//! Beyond "never panics": an accepted policy names only rules the engine
//! decides (each by its full id), never exempts uid 0, an executable
//! outside a root-owned system tree, a cgroup without a unit, or anything
//! by name (`comm`, `name`, `process`, `argv` refuse the file); at most
//! 64 exemptions per rule; its rendering parses back to the same policy.
//! A refusal names a line of the text.
//!
//! Lot 275 (review of #495, N6): the start's reading (`boot_policy`) — a
//! policy is in force at the start exactly when the text with each
//! `enforce` of a rule `ENFORCE_REFUSED` names rewritten as `alert` parses,
//! and it is that policy (its source aside); it names a demoted line iff
//! there was one; otherwise the built-in defaults, with the parse error.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::decision::rule_policy::{
    boot_policy, enforce_refused, parse, resolve_rule, Exemption, MAX_EXEMPTIONS_PER_RULE,
};

/// `text` with each `enforce <rule>` line of a rule whose enforce is
/// refused rewritten as `alert <rule>`, and whether one was.
fn demoted(text: &str) -> (String, bool) {
    let mut any = false;
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let (content, comment) = match line.split_once('#') {
                Some((c, rest)) => (c, Some(rest)),
                None => (line, None),
            };
            // as `parse` reads a line: the content before `#`, trimmed
            let content = content.trim();
            let w: Vec<&str> = content.split_whitespace().collect();
            let refused = matches!(w.as_slice(), ["enforce", r]
                if !content.chars().any(char::is_control)
                    && resolve_rule(r).ok().and_then(enforce_refused).is_some());
            if refused {
                any = true;
                let mut out = format!("alert {}", w[1]);
                if let Some(c) = comment {
                    out.push('#');
                    out.push_str(c);
                }
                out
            } else {
                line.to_string()
            }
        })
        .collect();
    (lines.join("\n"), any)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // the start's reading
    let boot = boot_policy(Some((std::path::Path::new("/etc/northnarrow/rule-policy.local"), text)));
    let (rewritten, any) = demoted(text);
    match parse(&rewritten) {
        Ok(mut want) => {
            assert_eq!(boot.degraded, None);
            assert_eq!(boot.demoted.is_some(), any, "{text:?}");
            want.source = boot.policy.source.clone();
            assert_eq!(boot.policy, want, "{text:?}");
            if any {
                assert!(parse(text).is_err(), "a refused enforce accepted to be signed");
            }
        }
        Err(_) => {
            assert!(boot.policy.is_builtin() && boot.demoted.is_none(), "{text:?}");
            assert!(boot.degraded.is_some());
        }
    }
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
