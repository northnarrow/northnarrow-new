//! Lot 316, the review of #548 (F1, F3): a unit glob matched as systemctl
//! matches it — glibc's `fnmatch(pattern, name, FNM_NOESCAPE)` against the
//! names of the units in memory — in time linear in the product of the two
//! lengths.
//!
//! The first matcher backtracked recursively at each `*`: a 21-byte
//! `systemctl stop '********************Z'`, refused by systemctl, held the
//! agent's decision thread for hours (its cost grew about eightfold per
//! star). This one compiles the pattern once and matches with a single
//! backtrack point, the last `*` (the classic two-pointer algorithm):
//! `O(|pattern| · |name|)`, both capped ([`PATTERN_MAX`], [`NAME_MAX`]).
//!
//! systemd's semantics (`unit_name_mangle_with_suffix` keeps a glob as it
//! is; `strv_fnmatch` uses `FNM_NOESCAPE`): `*`, `?`, a bracket expression
//! (`!` or `^` negates, `a-z`, a `]` first is itself, the POSIX classes
//! `[:alpha:]` …, a collating symbol `[.x.]` and an equivalence class
//! `[=x=]` as the character `x` in the C locale), a `[` with no closing `]`
//! is itself, and `\` is an ordinary character. `/` and a leading `.` are
//! ordinary characters too (no `FNM_PATHNAME`, no `FNM_PERIOD`).

/// The longest pattern compiled: a longer one (more than an argv's 512
/// bytes, which the exec event keeps) is taken to match every name — toward
/// a detection.
pub(super) const PATTERN_MAX: usize = 1024;
/// The longest unit name systemd accepts (`UNIT_NAME_MAX` is 256 with its
/// NUL).
pub(super) const NAME_MAX: usize = 255;

/// One element of a compiled glob.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Elem {
    /// `*`: any run of characters.
    Star,
    /// `?`: any one character.
    One,
    /// A character, as itself.
    Char(char),
    /// A bracket expression.
    Set { negate: bool, items: Vec<Item> },
}

/// One member of a bracket expression.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Item {
    Char(char),
    Range(char, char),
    Class(Class),
    /// A class name glibc does not know: any one character (toward a
    /// detection; glibc refuses the pattern).
    AnyClass,
}

/// The POSIX character classes, in the C locale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Alnum,
    Alpha,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Xdigit,
}

impl Class {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "alnum" => Self::Alnum,
            "alpha" => Self::Alpha,
            "blank" => Self::Blank,
            "cntrl" => Self::Cntrl,
            "digit" => Self::Digit,
            "graph" => Self::Graph,
            "lower" => Self::Lower,
            "print" => Self::Print,
            "punct" => Self::Punct,
            "space" => Self::Space,
            "upper" => Self::Upper,
            "xdigit" => Self::Xdigit,
            _ => return None,
        })
    }

    fn holds(self, c: char) -> bool {
        match self {
            Self::Alnum => c.is_ascii_alphanumeric(),
            Self::Alpha => c.is_ascii_alphabetic(),
            Self::Blank => c == ' ' || c == '\t',
            Self::Cntrl => c.is_ascii_control(),
            Self::Digit => c.is_ascii_digit(),
            Self::Graph => c.is_ascii_graphic(),
            Self::Lower => c.is_ascii_lowercase(),
            Self::Print => c.is_ascii_graphic() || c == ' ',
            Self::Punct => c.is_ascii_punctuation(),
            Self::Space => c.is_ascii_whitespace() || c == '\x0b',
            Self::Upper => c.is_ascii_uppercase(),
            Self::Xdigit => c.is_ascii_hexdigit(),
        }
    }
}

impl Elem {
    /// The element matches the character `c` (never `Star`).
    fn one(&self, c: char) -> bool {
        match self {
            Elem::Star => false,
            Elem::One => true,
            Elem::Char(x) => *x == c,
            Elem::Set { negate, items } => {
                let hit = items.iter().any(|i| match i {
                    Item::Char(x) => *x == c,
                    Item::Range(a, b) => *a <= c && c <= *b,
                    Item::Class(k) => k.holds(c),
                    Item::AnyClass => true,
                });
                hit != *negate
            }
        }
    }
}

/// The bracket expression at `p[at]` (the `[`): what it is and the index
/// after its `]`; `None` when it has no closing `]` (the `[` is then
/// itself).
fn bracket(p: &[char], at: usize) -> Option<(Elem, usize)> {
    let mut i = at + 1;
    let negate = matches!(p.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let mut items = Vec::new();
    let mut first = true;
    loop {
        let c = *p.get(i)?;
        if c == ']' && !first {
            return Some((Elem::Set { negate, items }, i + 1));
        }
        first = false;
        // `[:class:]`, `[.x.]`, `[=x=]`
        if c == '[' && matches!(p.get(i + 1), Some(':' | '.' | '=')) {
            let kind = p[i + 1];
            let start = i + 2;
            if let Some(end) = special_end(p, kind, start) {
                let inner: String = p[start..end].iter().collect();
                items.push(match kind {
                    ':' => Class::named(&inner).map_or(Item::AnyClass, Item::Class),
                    // a collating symbol or an equivalence class: one
                    // character in the C locale, else any (toward a
                    // detection)
                    _ => {
                        let mut cs = inner.chars();
                        match (cs.next(), cs.next()) {
                            (Some(x), None) => Item::Char(x),
                            _ => Item::AnyClass,
                        }
                    }
                });
                i = end + 2;
                continue;
            }
        }
        // a range, unless its `-` is the last member
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|e| *e != ']') {
            items.push(Item::Range(c, p[i + 2]));
            i += 3;
            continue;
        }
        items.push(Item::Char(c));
        i += 1;
    }
}

/// The review of #548, re-check (N2): where the `[:`, `[.` or `[=` (`kind`)
/// whose name starts at `p[start]` ends — the index of its closing `:`, `.`
/// or `=` — as glibc's `fnmatch_loop.c` ends it; `None` when it is no such
/// element (its `[` is then an ordinary member):
/// - `[:` names a class in bytes `a`–`y` up to the first `:]`; any other
///   byte first ends the attempt (`[a[:]uditd.servic[:e:]` is the members
///   `a`, `[`, `:`, and it stops auditd);
/// - `[=` holds exactly one character, then `=]`;
/// - `[.` runs to the first `.]` (a name other than one character makes
///   glibc match nothing in the C locale: any reading of it is at least as
///   wide).
fn special_end(p: &[char], kind: char, start: usize) -> Option<usize> {
    match kind {
        ':' => {
            let mut k = start;
            loop {
                match p.get(k)? {
                    ':' if p.get(k + 1) == Some(&']') => return Some(k),
                    'a'..='y' => k += 1,
                    _ => return None,
                }
            }
        }
        '=' => (p.get(start).is_some()
            && p.get(start + 1) == Some(&'=')
            && p.get(start + 2) == Some(&']'))
        .then_some(start + 1),
        _ => (start..p.len().saturating_sub(1)).find(|&k| p[k] == kind && p[k + 1] == ']'),
    }
}

/// `pattern`, compiled; `None` when it is longer than [`PATTERN_MAX`].
fn compile(pattern: &str) -> Option<Vec<Elem>> {
    let p: Vec<char> = pattern.chars().collect();
    if p.len() > PATTERN_MAX {
        return None;
    }
    let mut out = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            '*' => {
                // a run of stars is one
                if out.last() != Some(&Elem::Star) {
                    out.push(Elem::Star);
                }
                i += 1;
            }
            '?' => {
                out.push(Elem::One);
                i += 1;
            }
            '[' => match bracket(&p, i) {
                Some((e, next)) => {
                    out.push(e);
                    i = next;
                }
                None => {
                    out.push(Elem::Char('['));
                    i += 1;
                }
            },
            c => {
                out.push(Elem::Char(c));
                i += 1;
            }
        }
    }
    Some(out)
}

/// `fnmatch(pattern, name, FNM_NOESCAPE)`, in `O(|pattern| · |name|)`. A
/// pattern longer than [`PATTERN_MAX`] matches every name; a name longer
/// than [`NAME_MAX`] (no unit's) none.
pub(super) fn fnmatch(pattern: &str, name: &str) -> bool {
    let Some(p) = compile(pattern) else {
        return true;
    };
    let n: Vec<char> = name.chars().collect();
    if n.len() > NAME_MAX {
        return false;
    }
    matches(&p, &n)
}

/// The two-pointer match: on a mismatch, go back to the last `*` and let it
/// take one more character.
fn matches(p: &[Elem], n: &[char]) -> bool {
    let (mut pi, mut ni) = (0, 0);
    // the last star: the element after it, and the name index it resumes at
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        match p.get(pi) {
            Some(Elem::Star) => {
                star = Some((pi + 1, ni));
                pi += 1;
            }
            Some(e) if e.one(n[ni]) => {
                pi += 1;
                ni += 1;
            }
            _ => match star {
                Some((after, from)) => {
                    pi = after;
                    ni = from + 1;
                    star = Some((after, from + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|e| *e == Elem::Star)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reference: the same compiled pattern, matched by dynamic
    /// programming over every (pattern, name) prefix — another algorithm.
    fn reference(pattern: &str, name: &str) -> bool {
        let Some(p) = compile(pattern) else {
            return true;
        };
        let n: Vec<char> = name.chars().collect();
        // m[i][j]: p[..i] matches n[..j]
        let mut m = vec![vec![false; n.len() + 1]; p.len() + 1];
        m[0][0] = true;
        for i in 1..=p.len() {
            for j in 0..=n.len() {
                m[i][j] = match &p[i - 1] {
                    Elem::Star => m[i - 1][j] || (j > 0 && m[i][j - 1]),
                    e => j > 0 && m[i - 1][j - 1] && e.one(n[j - 1]),
                };
            }
        }
        m[p.len()][n.len()]
    }

    /// glibc's `fnmatch` with `FNM_NOESCAPE`, as systemd uses it (cases
    /// checked against `systemctl list-units` on systemd 255 by the review
    /// of #548, and fnmatch(3)).
    #[test]
    fn units_match_as_systemd_matches_them() {
        for (p, n, want) in [
            ("*uditd*", "auditd.service", true),
            ("audit?.service", "auditd.service", true),
            ("audit?", "auditd.service", false),
            ("[a]uditd.service", "auditd.service", true),
            ("[!b]uditd.service", "auditd.service", true),
            ("[^a]uditd.service", "auditd.service", false),
            ("[a-c]uditd.*", "auditd.service", true),
            ("[]a]uditd.service", "auditd.service", true),
            ("[[:alpha:]]uditd.service", "auditd.service", true),
            ("[[:digit:]]uditd.service", "auditd.service", false),
            ("[![:digit:]]uditd.service", "auditd.service", true),
            ("[[.a.]]uditd.service", "auditd.service", true),
            ("[[=a=]]uditd.service", "auditd.service", true),
            ("[[:nosuch:]]uditd.service", "auditd.service", true),
            (
                "snap.*.service",
                "snap.amazon-ssm-agent.amazon-ssm-agent.service",
                true,
            ),
            // FNM_NOESCAPE: `\` is itself (systemd does not match
            // `systemd\-journald.service`)
            ("\\auditd.service", "auditd.service", false),
            ("a\\*", "a\\x", true),
            ("*", "auditd.service", true),
            ("[a", "[a", true),
            // an unclosed `[` is itself, no wildcard
            ("[a", "xa", false),
            // a range's upper bound; a class holds its own characters only;
            // a collating symbol is its character
            ("[a-c]x", "dx", false),
            ("[[:alpha:]]x", "1x", false),
            ("[[:upper:]]x", "ax", false),
            ("[[.a.]]x", "bx", false),
            ("[[=a=]]x", "bx", false),
            ("auditd.service?", "auditd.service", false),
            ("a*b*c*d*e*f*g", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false),
            // the re-check of #548 (N2), with glibc's fnmatch: a `[:` whose
            // name meets a byte outside `a`–`y` before `:]` is no class, a
            // `[=` holds one character — the `[` is then a member and the
            // bracket ends at the next `]`
            ("[a[:]uditd.servic[:e:]", "auditd.service", true),
            ("[[:alpha]uditd.service", "auditd.service", true),
            ("[[:alpha]uditd.service", ":uditd.service", true),
            ("[[:z:]]x", "zx", false),
            ("[[:z:]]x", ":]x", true),
            ("[[=a]uditd.servic[=e=]", "auditd.service", true),
            ("[[==]]x", "=]x", true),
            ("[[===]]x", "=x", true),
            ("[[=ab=]]x", "ax", false),
            // glibc matches nothing here (a name of two characters, in the
            // C locale): any character is wider
            ("[[.ab.]]x", "ax", true),
        ] {
            assert_eq!(fnmatch(p, n), want, "{p} {n}");
            assert_eq!(reference(p, n), want, "reference: {p} {n}");
        }
    }

    /// F1: twenty stars and more cost a few microseconds per name, not
    /// hours: two hundred stars then a `Z`, against a 255-byte name.
    #[test]
    fn many_stars_match_in_linear_time() {
        let name = "a".repeat(NAME_MAX);
        for stars in [20, 21, 50, 200] {
            let p = format!("{}Z", "*".repeat(stars));
            let t = std::time::Instant::now();
            assert!(!fnmatch(&p, &name));
            assert!(!fnmatch(&format!("{}a*Z", "*a".repeat(stars)), &name));
            assert!(
                t.elapsed() < std::time::Duration::from_millis(50),
                "{stars} stars: {:?}",
                t.elapsed()
            );
        }
        // the caps: a pattern past PATTERN_MAX matches, a name past NAME_MAX
        // does not
        assert!(fnmatch(&"x".repeat(PATTERN_MAX + 1), "auditd.service"));
        assert!(!fnmatch("*", &"a".repeat(NAME_MAX + 1)));
    }

    /// The two-pointer match agrees with the dynamic programme on every
    /// pattern and name of a deterministic generator (stars, `?`, brackets,
    /// literals, over a small alphabet).
    #[test]
    fn the_linear_match_agrees_with_the_reference() {
        struct Gen(u64);
        impl Gen {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
        }
        let atoms = [
            "*",
            "*",
            "?",
            "a",
            "b",
            ".",
            "[ab]",
            "[!a]",
            "[[:alpha:]]",
            "[a-b]",
            "\\",
            "[",
        ];
        let letters = ['a', 'b', '.', 'c', '\\', '['];
        let mut g = Gen(0x316_548);
        let mut checked = 0;
        for _ in 0..20_000 {
            let plen = (g.next() % 7) as usize;
            let p: String = (0..plen)
                .map(|_| atoms[(g.next() % atoms.len() as u64) as usize])
                .collect();
            let nlen = (g.next() % 8) as usize;
            let n: String = (0..nlen)
                .map(|_| letters[(g.next() % letters.len() as u64) as usize])
                .collect();
            assert_eq!(fnmatch(&p, &n), reference(&p, &n), "{p:?} {n:?}");
            checked += 1;
        }
        assert_eq!(checked, 20_000);
    }
}
