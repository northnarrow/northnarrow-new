//! Lot 312 (external bug hunt, edition 1.4, family F2): where a cgroup
//! path is, decided by its components from the root of the hierarchy —
//! never by a suffix or a substring.
//!
//! A user whose systemd manager delegates a subtree to it
//! (`user@<uid>.service` is `Delegate=yes`) names the cgroups in it as it
//! likes: `…/user@1000.service/northnarrow.slice/blocked.scope` ends with
//! the agent's blocked scope, and a container's
//! `…/docker-<id>.scope/system.slice/ssh.service` with the host's SSH unit.
//! Compared by suffix (`ends_with`) or by substring (`contains`), the
//! response took the namesake for its own scope — a block that answered
//! `Blocked` and moved nothing, while the drop rule, which names the scope
//! from the root, filtered nothing — and the guard took the container's
//! unit for the host's. A path is its components here, and a cgroup is at
//! or under another only when every component of the other, from the
//! root, is its own.

/// The components of an absolute cgroup path (`/a/b` → `["a", "b"]`, `/`
/// → `[]`). `None` for a path that is not absolute, or that has an empty,
/// `.` or `..` component (a cgroup namespace shows `/../..` for a cgroup
/// outside it, and the kernel never shows `//` or a trailing `/`): such a
/// path is at or under nothing.
pub fn components(path: &str) -> Option<Vec<&str>> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    parts
        .iter()
        .all(|c| !c.is_empty() && *c != "." && *c != "..")
        .then_some(parts)
}

/// `path` is the cgroup `base` or a cgroup below it: every component of
/// `base`, from the root, is the same component of `path`.
pub fn cgroup_at_or_under(path: &str, base: &str) -> bool {
    match (components(path), components(base)) {
        (Some(p), Some(b)) => p.len() >= b.len() && p[..b.len()] == b[..],
        _ => false,
    }
}

/// `path` is the cgroup `base` itself.
pub fn cgroup_at(path: &str, base: &str) -> bool {
    match (components(path), components(base)) {
        (Some(p), Some(b)) => p == b,
        _ => false,
    }
}

/// The cgroup v2 path of a `/proc/<pid>/cgroup` text (its `0::` line, the
/// line end off). `None` when the text has none (a host without the
/// unified hierarchy).
pub fn unified_path(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim_end)
}

/// The path of the agent's scope `name` (`blocked.scope`) in its slice
/// `slice` (`northnarrow.slice`), from the root: `/northnarrow.slice/
/// blocked.scope`.
pub fn scope_path(slice: &str, name: &str) -> String {
    format!("/{slice}/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string model the helpers must agree with on well-formed paths:
    /// equal, or `base` followed by a `/` and more.
    fn model_at_or_under(path: &str, base: &str) -> bool {
        if base == "/" {
            return true;
        }
        path == base || path.strip_prefix(base).is_some_and(|r| r.starts_with('/'))
    }

    /// Every path of up to `depth` components drawn from `alphabet`.
    fn paths(alphabet: &[&str], depth: usize) -> Vec<String> {
        let mut out = vec!["/".to_string()];
        let mut layer = vec![String::new()];
        for _ in 0..depth {
            let mut next = Vec::new();
            for p in &layer {
                for c in alphabet {
                    next.push(format!("{p}/{c}"));
                }
            }
            out.extend(next.iter().cloned());
            layer = next;
        }
        out
    }

    const ALPHABET: &[&str] = &[
        "northnarrow.slice",
        "blocked.scope",
        "user@1000.service",
        "blocked.scope.bak",
        "x",
    ];

    /// Property, over every well-formed path of up to four components of
    /// the alphabet and every base among them: the components agree with
    /// the string model, `at` is `at_or_under` at the same depth, and a
    /// path under a base keeps being under it whatever is added below.
    #[test]
    fn components_agree_with_the_string_model_on_well_formed_paths() {
        let all = paths(ALPHABET, 4);
        let bases = paths(ALPHABET, 2);
        let mut checked = 0;
        for b in &bases {
            for p in &all {
                let got = cgroup_at_or_under(p, b);
                assert_eq!(got, model_at_or_under(p, b), "{p} under {b}");
                assert_eq!(
                    cgroup_at(p, b),
                    got && components(p).unwrap().len() == components(b).unwrap().len(),
                    "{p} at {b}"
                );
                if got {
                    let below = format!("{}/x", p.trim_end_matches('/'));
                    assert!(cgroup_at_or_under(&below, b), "{below} under {b}");
                }
                checked += 1;
            }
        }
        assert!(checked > 10_000, "{checked}");
    }

    /// Property: a namesake — the base's components anywhere but from the
    /// root — is never at or under it, while a suffix test takes it for the
    /// base (BUG-91, BUG-114, BUG-117).
    #[test]
    fn a_namesake_below_any_other_cgroup_is_neither_at_nor_under() {
        let prefixes = paths(ALPHABET, 3);
        for base in [
            "/northnarrow.slice/blocked.scope",
            "/northnarrow.slice/throttled.scope",
            "/system.slice/ssh.service",
        ] {
            for q in prefixes.iter().filter(|q| *q != "/") {
                let namesake = format!("{q}{base}");
                assert!(namesake.ends_with(base), "premise: {namesake}");
                assert!(!cgroup_at(&namesake, base), "{namesake} at {base}");
                // under only when the prefix itself starts with the base
                assert_eq!(
                    cgroup_at_or_under(&namesake, base),
                    model_at_or_under(q, base),
                    "{namesake} under {base}"
                );
                assert!(!cgroup_at_or_under(&format!("{namesake}/kill-1"), "/nope"));
            }
        }
    }

    /// Malformed paths are at or under nothing (and nothing is under them).
    #[test]
    fn a_malformed_path_is_nowhere() {
        let base = "/northnarrow.slice/blocked.scope";
        for bad in [
            "",
            "northnarrow.slice/blocked.scope",
            "/northnarrow.slice//blocked.scope",
            "/northnarrow.slice/blocked.scope/",
            "/northnarrow.slice/./blocked.scope",
            "/../../northnarrow.slice/blocked.scope",
            "/northnarrow.slice/blocked.scope/..",
            "/x/../northnarrow.slice/blocked.scope",
        ] {
            assert!(!cgroup_at_or_under(bad, base), "{bad:?}");
            assert!(!cgroup_at(bad, base), "{bad:?}");
            assert!(!cgroup_at_or_under(base, bad), "{bad:?} as the base");
        }
        assert_eq!(components("/"), Some(Vec::new()));
        assert!(
            cgroup_at_or_under(base, "/"),
            "everything is under the root"
        );
    }

    /// A seeded generator of paths with any bytes in their components
    /// (spaces, `@`, `:`, dots, unicode), against the string model wherever
    /// the path is well formed: no new dependency, the same cases every
    /// run.
    #[test]
    fn random_components_agree_with_the_string_model() {
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let pieces = [
            "a",
            "b",
            "slice",
            ".scope",
            " ",
            "@",
            ":",
            "-",
            "é",
            "blocked",
            ".",
            "x.service",
        ];
        let comp = |next: &mut dyn FnMut() -> u64| {
            let n = 1 + (next() % 3) as usize;
            (0..n)
                .map(|_| pieces[(next() % pieces.len() as u64) as usize])
                .collect::<String>()
        };
        let path = |next: &mut dyn FnMut() -> u64| {
            let n = (next() % 5) as usize;
            let mut p = String::new();
            for _ in 0..n {
                p.push('/');
                p.push_str(&comp(next));
            }
            if p.is_empty() {
                p.push('/');
            }
            p
        };
        for _ in 0..20_000 {
            let base = path(&mut next);
            let p = if next() % 2 == 0 {
                format!("{base}{}", path(&mut next))
            } else {
                path(&mut next)
            };
            if components(&p).is_none() || components(&base).is_none() {
                // a `.` component: nowhere, and nothing under it
                assert!(!cgroup_at_or_under(&p, &base), "{p:?} under {base:?}");
                continue;
            }
            assert_eq!(
                cgroup_at_or_under(&p, &base),
                model_at_or_under(&p, &base),
                "{p:?} under {base:?}"
            );
        }
    }

    #[test]
    fn the_unified_line_is_read_and_its_end_trimmed() {
        assert_eq!(
            unified_path("12:pids:/x\n0::/northnarrow.slice/blocked.scope\r\n"),
            Some("/northnarrow.slice/blocked.scope")
        );
        assert_eq!(unified_path("1:name=systemd:/a.service\n"), None);
        assert_eq!(
            scope_path("northnarrow.slice", "blocked.scope"),
            "/northnarrow.slice/blocked.scope"
        );
    }
}
