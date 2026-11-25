//! Lot 332: the verifier's headroom of every program — the instructions the
//! kernel's verifier processed to accept it, against its limit of a million
//! per load (`BPF_COMPLEXITY_LIMIT_INSNS`) — and the lab's gate on it.
//!
//! Alpha testers run kernels the lab has never seen (RHEL and Alma 5.14,
//! Fedora, Arch, older 5.15 builds). A program near the limit on the lab's
//! kernels can be refused on one of theirs, and the agent then runs without
//! it. `verifier-check` (`crate::verifier_check`, lab builds) reads the count
//! of each load — `bpf_prog_info.verified_insns` where the kernel hands it
//! out (5.16 and later), otherwise the kernel's own counter read by a kprobe
//! event when the verifier finishes ([`kprobe_definition`]) — and fails a
//! kernel on which a program the agent loads processed more than
//! [`HEADROOM_BUDGET`], or on which its count could not be measured: an
//! unmeasured headroom is not a passing one.
//!
//! This module is the judgement and its parsing, kept apart from the loader
//! so that it is compiled and tested in every build (the verifier check
//! itself is behind the lab feature).
//!
//! Lot 1.3 (plan S1, F6): the stack gate. The verifier refuses a call chain
//! whose frames (each rounded up to 32 bytes) add up to more than 512
//! bytes; a program at 512 is one local variable away from a refusal, on
//! any kernel. A program the agent needs whose deepest chain is over
//! [`STACK_BUDGET`] (448), or whose chain could not be read back, fails
//! the kernel too — except the programs of [`STACK_DEBT`], held each to
//! the chain it had when the gate came, until their lot brings them under
//! it. `xtask/tests/verifier_headroom.rs` holds the same gate on the built
//! object, without a kernel.

/// The verifier's limit on the instructions it processes for one load
/// (`BPF_COMPLEXITY_LIMIT_INSNS`, the same from 5.2 to 7.0).
pub const VERIFIER_INSN_LIMIT: u32 = 1_000_000;

/// The gate: 90% of [`VERIFIER_INSN_LIMIT`]. Above it, a program is one
/// compiler or kernel change away from a refusal on a kernel the lab has
/// not seen.
pub const HEADROOM_BUDGET: u32 = 900_000;

/// The programs the report lists by their count, highest first.
pub const TOP: usize = 10;

/// The verifier's limit on the stack of a call chain (`MAX_BPF_STACK`).
pub const STACK_LIMIT: u32 = 512;

/// Lot 1.3 (plan S1, F6): the stack gate, 448 of [`STACK_LIMIT`]'s 512
/// bytes — two 32-byte frames of room on the deepest call chain.
pub const STACK_BUDGET: u32 = 448;

/// Lot 1.3: the programs over [`STACK_BUDGET`] when the gate came, each
/// with the chain it may not exceed. Lot 1.4 owns their code (the file-open
/// sensor's global functions, `tcp_close`, the `bpf()` observer's) and
/// takes them off; the S1 exit test is an empty list. A program brought
/// under the budget leaves the list (the xtask ratchet fails on an entry
/// that is no longer over it).
pub const STACK_DEBT: &[(&str, u32)] = &[
    ("bpf_syscall_observe", 480),
    ("fim_file_open_sensor", 480),
    ("tcp_close", 480),
];

/// The deepest call chain `prog` may have: its debt's, else the budget.
pub fn stack_allowed(prog: &str) -> u32 {
    STACK_DEBT
        .iter()
        .find(|(n, _)| *n == prog)
        .map_or(STACK_BUDGET, |(_, c)| *c)
}

/// The environment variable that LOWERS the budget for one run (to see the
/// gate fail on a kernel, or to hold a lot to a tighter target). A value
/// above [`HEADROOM_BUDGET`], or not a number, is ignored: the gate is never
/// relaxed from the environment.
pub const BUDGET_ENV: &str = "NN_VERIFIER_CHECK_BUDGET";

/// The bytes of a program name the kernel keeps (`BPF_OBJ_NAME_LEN` 16,
/// with its NUL): aya truncates the name it passes to `BPF_PROG_LOAD` to
/// them, and the kprobe event reads them back.
pub const KERNEL_NAME_LEN: usize = 15;

/// The budget of this run and, when the environment asked for something
/// else, what was done with it.
pub fn budget_from(env: Option<&str>) -> (u32, Option<String>) {
    let Some(raw) = env.map(str::trim).filter(|s| !s.is_empty()) else {
        return (HEADROOM_BUDGET, None);
    };
    match raw.parse::<u32>() {
        Ok(n) if n <= HEADROOM_BUDGET => (
            n,
            Some(format!(
                "{BUDGET_ENV}={n}: the budget lowered from {HEADROOM_BUDGET}"
            )),
        ),
        Ok(n) => (
            HEADROOM_BUDGET,
            Some(format!(
                "{BUDGET_ENV}={n} ignored: the budget can only be lowered (kept at {HEADROOM_BUDGET})"
            )),
        ),
        Err(_) => (
            HEADROOM_BUDGET,
            Some(format!(
                "{BUDGET_ENV}={raw:?} ignored: not a number (kept at {HEADROOM_BUDGET})"
            )),
        ),
    }
}

/// The name the kernel keeps for `prog` (its first [`KERNEL_NAME_LEN`]
/// bytes, as aya passes it).
pub fn kernel_name(prog: &str) -> &str {
    if prog.len() <= KERNEL_NAME_LEN {
        return prog;
    }
    let mut end = KERNEL_NAME_LEN;
    while !prog.is_char_boundary(end) {
        end -= 1;
    }
    &prog[..end]
}

/// The byte offsets the kprobe event dereferences, from the running
/// kernel's BTF: `bpf_verifier_env.insn_processed` (a `u32`),
/// `bpf_verifier_env.prog`, `bpf_prog.aux`, `bpf_prog_aux.name`, and (the
/// review of #551, F3) `bpf_prog.tag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOffsets {
    pub insn_processed: usize,
    pub prog: usize,
    pub aux: usize,
    pub name: usize,
    pub tag: usize,
}

/// The `kprobe_events` line of the probe: at the entry of `func` (the
/// verifier's last pass over an accepted program, `check_max_stack_depth`,
/// whose first argument is the verifier's state), the count the verifier
/// reached, the program's tag and its name. `arg` is how the first
/// argument is fetched (`$arg1`, or the architecture's register on a kernel
/// without argument access).
///
/// The review of #551 (F3): the name the kernel keeps is 15 bytes, which
/// several of the agent's programs share (`dns_answer_v4_ret4/5/6`,
/// `sched_process_exec` / `_nostdio`, …). The tag — the SHA-1 of the
/// program's instructions, computed before the verifier runs
/// (`bpf_prog_calc_tag`) and handed out in the program info — tells them
/// apart. The id cannot: it is given after the verifier accepted the
/// program (`bpf_prog_alloc_id`), 0 when the probe fires.
pub fn kprobe_definition(
    group: &str,
    event: &str,
    func: &str,
    arg: &str,
    o: ProbeOffsets,
) -> String {
    format!(
        "p:{group}/{event} {func} insn=+{}({arg}):u32 tag=+{}(+{}({arg})):x64 \
         name=+{}(+{}(+{}({arg}))):string",
        o.insn_processed, o.tag, o.prog, o.name, o.aux, o.prog
    )
}

/// What the probe prints for a program whose program info gives `tag`
/// (aya's, the eight bytes read big-endian): the same eight bytes read as
/// a `u64` in this machine's order (`:x64`).
pub fn probe_tag(tag: u64) -> u64 {
    u64::from_ne_bytes(tag.to_be_bytes())
}

/// `(count, tag, name)` of one line of the probe's trace
/// (`… insn_processed: (check_max_stack_depth+0x0/0x2b0) insn=821228
/// tag=0x3e1f… name="fim_file_open_s"`).
pub fn parse_trace_line(line: &str) -> Option<(u32, u64, &str)> {
    let rest = &line[line.find(" insn=")? + " insn=".len()..];
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let count = rest[..digits].parse::<u32>().ok()?;
    let rest = rest[digits..].strip_prefix(" tag=0x")?;
    let hex = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    let tag = u64::from_str_radix(&rest[..hex], 16).ok()?;
    let rest = &rest[hex..];
    let name = rest.strip_prefix(" name=\"")?;
    let name = &name[..name.find('"')?];
    Some((count, tag, name))
}

/// The count of `prog`'s load in `trace` (the probe's buffer, cleared
/// before the load): its last line naming the program with the tag its
/// program info gives (`tag`, aya's). `None` when the probe did not fire
/// for it — a line of another program sharing its 15-byte name is not its.
pub fn count_in_trace(trace: &str, prog: &str, tag: u64) -> Option<u32> {
    let want = (kernel_name(prog), probe_tag(tag));
    trace
        .lines()
        .rev()
        .filter(|l| !l.starts_with('#'))
        .filter_map(parse_trace_line)
        .find(|(_, t, n)| (*n, *t) == want)
        .map(|(c, _, _)| c)
}

/// Where a count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `bpf_prog_info.verified_insns` (5.16 and later).
    Info,
    /// The kprobe event (kernels whose program info has no count: 5.15).
    Kprobe,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Info => "program info",
            Source::Kprobe => "kprobe",
        }
    }
}

/// One loaded program the agent needs, as the gate sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measured {
    pub name: String,
    /// The program info's count, when the kernel gives one.
    pub info: Option<u32>,
    /// The kprobe's count, when the probe ran and fired.
    pub kprobe: Option<u32>,
    /// Lot 1.3: its deepest call chain in bytes (frames rounded up to 32,
    /// as the verifier adds them), read back from the translated image;
    /// `None` when the kernel did not hand the image out.
    pub stack: Option<u32>,
}

impl Measured {
    /// The count the gate judges: the program info's (the kernel's own
    /// field), else the kprobe's.
    pub fn processed(&self) -> Option<(u32, Source)> {
        self.info
            .map(|n| (n, Source::Info))
            .or(self.kprobe.map(|n| (n, Source::Kprobe)))
    }
}

/// The gate's judgement of one kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub budget: u32,
    /// Every measured program, highest count first (ties by name).
    pub ranked: Vec<(String, u32, Source)>,
    /// The programs over the budget, highest first.
    pub over: Vec<(String, u32)>,
    /// The programs with no count from either source.
    pub unmeasured: Vec<String>,
    /// Programs measured both ways whose counts differ (the kprobe's
    /// method checked against the kernel's field).
    pub disagree: Vec<(String, u32, u32)>,
    /// Programs measured both ways.
    pub cross_checked: usize,
    /// Lot 1.3: every program's deepest call chain, deepest first (ties by
    /// name).
    pub stack_ranked: Vec<(String, u32)>,
    /// The programs whose chain is over what they may have
    /// ([`stack_allowed`]), with it.
    pub stack_over: Vec<(String, u32)>,
    /// The programs of [`STACK_DEBT`] over the budget and within their
    /// debt: `(name, chain, debt)`.
    pub stack_debt: Vec<(String, u32, u32)>,
    /// The programs whose chain could not be read back.
    pub stack_unmeasured: Vec<String>,
}

impl Verdict {
    pub fn passes(&self) -> bool {
        self.over.is_empty()
            && self.unmeasured.is_empty()
            && self.stack_over.is_empty()
            && self.stack_unmeasured.is_empty()
    }
}

/// Judge `programs` (the loaded programs the agent needs) against `budget`.
pub fn judge(programs: &[Measured], budget: u32) -> Verdict {
    let mut ranked: Vec<(String, u32, Source)> = programs
        .iter()
        .filter_map(|m| m.processed().map(|(n, s)| (m.name.clone(), n, s)))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let over = ranked
        .iter()
        .filter(|(_, n, _)| *n > budget)
        .map(|(name, n, _)| (name.clone(), *n))
        .collect();
    let unmeasured = programs
        .iter()
        .filter(|m| m.processed().is_none())
        .map(|m| m.name.clone())
        .collect();
    let both: Vec<(&Measured, u32, u32)> = programs
        .iter()
        .filter_map(|m| Some((m, m.info?, m.kprobe?)))
        .collect();
    let disagree = both
        .iter()
        .filter(|(_, i, k)| i != k)
        .map(|(m, i, k)| (m.name.clone(), *i, *k))
        .collect();
    let mut stack_ranked: Vec<(String, u32)> = programs
        .iter()
        .filter_map(|m| Some((m.name.clone(), m.stack?)))
        .collect();
    stack_ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let stack_over = stack_ranked
        .iter()
        .filter(|(n, c)| *c > stack_allowed(n))
        .cloned()
        .collect();
    let stack_debt = stack_ranked
        .iter()
        .filter(|(n, c)| *c > STACK_BUDGET && *c <= stack_allowed(n))
        .map(|(n, c)| (n.clone(), *c, stack_allowed(n)))
        .collect();
    let stack_unmeasured = programs
        .iter()
        .filter(|m| m.stack.is_none())
        .map(|m| m.name.clone())
        .collect();
    Verdict {
        budget,
        ranked,
        over,
        unmeasured,
        disagree,
        cross_checked: both.len(),
        stack_ranked,
        stack_over,
        stack_debt,
        stack_unmeasured,
    }
}

/// Lot 1.3: the report's stack line — the deepest chains against the
/// gate, and the debt held.
pub fn stack_line(v: &Verdict) -> String {
    let top: Vec<String> = v
        .stack_ranked
        .iter()
        .take(5)
        .map(|(n, c)| format!("{n} {c}"))
        .collect();
    let debt = if v.stack_debt.is_empty() {
        "no debt over it".to_string()
    } else {
        format!(
            "held to their debt: {}",
            v.stack_debt
                .iter()
                .map(|(n, c, d)| format!("{n} {c} of {d}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "stack: {} programs' deepest call chains read back, {} not; gate {STACK_BUDGET} of the \
         verifier's {STACK_LIMIT} bytes, {debt}; deepest: {}",
        v.stack_ranked.len(),
        v.stack_unmeasured.len(),
        if top.is_empty() {
            "none".to_string()
        } else {
            top.join(", ")
        }
    )
}

/// `n` as a share of the gate ([`HEADROOM_BUDGET`], 900,000), one decimal
/// (`92.3%`) — lot 1.1 (F8b-1, P3): the gate the nightly fails above, not
/// the kernel's million (`830,908` read 83.1 % of the limit, and was 92.3 %
/// of the gate).
pub fn share_of_gate(n: u32) -> String {
    let tenths =
        (u64::from(n) * 1000 + u64::from(HEADROOM_BUDGET) / 2) / u64::from(HEADROOM_BUDGET);
    format!("{}.{}%", tenths / 10, tenths % 10)
}

/// The report's headroom section: the counts' sources, the top [`TOP`], and
/// the verdict line (`== verifier headroom <kernel>: OK|FAIL …`), the one a
/// CI step quotes.
pub fn report(kernel: &str, v: &Verdict) -> Vec<String> {
    let mut out = Vec::new();
    let from = |s: Source| v.ranked.iter().filter(|r| r.2 == s).count();
    out.push(format!(
        "verifier headroom: {} programs measured ({} from the program info, {} from the kprobe), \
         {} unmeasured; budget {} of the verifier's {} per load",
        v.ranked.len(),
        from(Source::Info),
        from(Source::Kprobe),
        v.unmeasured.len(),
        v.budget,
        VERIFIER_INSN_LIMIT
    ));
    if v.cross_checked > 0 {
        out.push(format!(
            "kprobe cross-check: {} of {} programs measured both ways agree{}",
            v.cross_checked - v.disagree.len(),
            v.cross_checked,
            if v.disagree.is_empty() {
                String::new()
            } else {
                format!(
                    "; differ: {}",
                    v.disagree
                        .iter()
                        .map(|(n, i, k)| format!("{n} info {i} kprobe {k}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ));
    }
    out.push(stack_line(v));
    out.push(String::new());
    out.push(format!("top {TOP} by instructions processed:"));
    out.push(String::new());
    out.push("| # | program | processed | of the 900k gate | source |".into());
    out.push("|---:|---|---:|---:|---|".into());
    for (i, (name, n, s)) in v.ranked.iter().take(TOP).enumerate() {
        out.push(format!(
            "| {} | {name} | {n} | {} | {} |",
            i + 1,
            share_of_gate(*n),
            s.label()
        ));
    }
    out.push(String::new());
    out.push(verdict_line(kernel, v));
    out
}

/// `== verifier headroom <kernel>: OK — highest …` or `… FAIL — …`.
pub fn verdict_line(kernel: &str, v: &Verdict) -> String {
    let highest = v.ranked.first().map_or_else(
        || "no program measured".to_string(),
        |(n, c, _)| format!("highest {n} {c} ({} of the 900k gate)", share_of_gate(*c)),
    );
    // lot 1.3: the stack's gate in the same line
    let highest = match v.stack_ranked.first() {
        Some((n, c)) => format!(
            "{highest}; stack chains within {STACK_BUDGET} of {STACK_LIMIT}{}, deepest {n} {c}",
            if v.stack_debt.is_empty() {
                String::new()
            } else {
                format!(" ({} held to their debt)", v.stack_debt.len())
            }
        ),
        None => highest,
    };
    if v.passes() {
        return format!(
            "== verifier headroom {kernel}: OK — every program within {} ({highest})",
            v.budget
        );
    }
    let mut why = Vec::new();
    if !v.over.is_empty() {
        why.push(format!(
            "over the budget {}: {}",
            v.budget,
            v.over
                .iter()
                .map(|(n, c)| format!("{n} {c}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !v.unmeasured.is_empty() {
        why.push(format!(
            "unmeasured (no count from the program info nor the kprobe): {}",
            v.unmeasured.join(", ")
        ));
    }
    if !v.stack_over.is_empty() {
        why.push(format!(
            "stack chain over the gate {STACK_BUDGET} of {STACK_LIMIT} bytes (or its debt): {}",
            v.stack_over
                .iter()
                .map(|(n, c)| format!("{n} {c}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !v.stack_unmeasured.is_empty() {
        why.push(format!(
            "stack chain not read back (the kernel did not hand out the translated image): {}",
            v.stack_unmeasured.join(", ")
        ));
    }
    format!("== verifier headroom {kernel}: FAIL — {}", why.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, info: Option<u32>, kprobe: Option<u32>) -> Measured {
        Measured {
            name: name.into(),
            info,
            kprobe,
            stack: Some(64),
        }
    }

    fn st(name: &str, stack: Option<u32>) -> Measured {
        Measured {
            stack,
            ..m(name, Some(1000), None)
        }
    }

    /// Lot 1.3 (plan S1, F6): `fim_rename_observe` was at 512 of 512 — a
    /// program one local away from a refusal passed the gate, which read
    /// the instructions only. A chain over 448 fails the kernel now, and
    /// so does one not read back; a debt's program is held to its own
    /// chain, never above it.
    #[test]
    fn the_gate_fails_a_stack_chain_over_448_or_not_read_back() {
        let v = judge(&[st("fim_rename_observe", Some(512))], HEADROOM_BUDGET);
        assert!(!v.passes(), "{v:?}");
        assert_eq!(v.stack_over, vec![("fim_rename_observe".to_string(), 512)]);
        let line = verdict_line("5.15", &v);
        assert!(
            line.contains("stack chain over the gate 448 of 512 bytes"),
            "{line}"
        );
        assert!(line.contains("fim_rename_observe 512"), "{line}");

        let v = judge(
            &[st("a", Some(448)), st("b", Some(32)), st("c", Some(449))],
            HEADROOM_BUDGET,
        );
        assert_eq!(v.stack_over, vec![("c".to_string(), 449)]);
        assert_eq!(v.stack_ranked[0], ("c".to_string(), 449));
        assert_eq!(v.stack_ranked[1], ("a".to_string(), 448));

        let v = judge(&[st("a", Some(448))], HEADROOM_BUDGET);
        assert!(v.passes(), "{v:?}");
        let line = verdict_line("6.8", &v);
        assert!(
            line.contains("stack chains within 448 of 512, deepest a 448"),
            "{line}"
        );

        let v = judge(&[st("a", Some(448)), st("dark", None)], HEADROOM_BUDGET);
        assert!(!v.passes());
        assert_eq!(v.stack_unmeasured, vec!["dark".to_string()]);
        assert!(verdict_line("k", &v).contains("stack chain not read back"));

        // the debt: within it, held and reported; above it, a failure
        let (name, debt) = STACK_DEBT[0];
        let v = judge(&[st(name, Some(debt))], HEADROOM_BUDGET);
        assert!(v.passes(), "{v:?}");
        assert_eq!(v.stack_debt, vec![(name.to_string(), debt, debt)]);
        assert!(verdict_line("k", &v).contains("(1 held to their debt)"));
        assert!(stack_line(&v).contains(&format!("held to their debt: {name} {debt} of {debt}")));
        let v = judge(&[st(name, Some(debt + 32))], HEADROOM_BUDGET);
        assert!(!v.passes());
        assert!(v.stack_debt.is_empty());
        // under the budget, a debt's program is no debt any more
        let v = judge(&[st(name, Some(STACK_BUDGET))], HEADROOM_BUDGET);
        assert!(v.passes() && v.stack_debt.is_empty());
        assert!(stack_line(&v).contains("no debt over it"));
    }

    /// The debt only holds programs over the budget, each below the
    /// verifier's limit, once each; the fim programs of lot 1.3 are not in
    /// it.
    #[test]
    fn the_stack_debt_is_over_the_budget_and_below_the_limit() {
        assert_eq!(STACK_BUDGET, 448);
        assert_eq!(STACK_LIMIT, 512);
        let mut names: Vec<&str> = STACK_DEBT.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), STACK_DEBT.len());
        for (n, c) in STACK_DEBT {
            assert!(
                *c > STACK_BUDGET && *c <= STACK_LIMIT && c % 32 == 0,
                "{n} {c}"
            );
            assert_eq!(stack_allowed(n), *c);
        }
        for p in ["fim_rename_observe", "fim_unlink_observe", "exec_check_raw"] {
            assert_eq!(stack_allowed(p), STACK_BUDGET, "{p}");
        }
    }

    #[test]
    fn the_budget_can_only_be_lowered_from_the_environment() {
        assert_eq!(budget_from(None), (HEADROOM_BUDGET, None));
        assert_eq!(budget_from(Some("  ")), (HEADROOM_BUDGET, None));
        let (b, note) = budget_from(Some("500000"));
        assert_eq!(b, 500_000);
        assert!(note.unwrap().contains("lowered"));
        let (b, note) = budget_from(Some("950000"));
        assert_eq!(b, HEADROOM_BUDGET);
        assert!(note.unwrap().contains("only be lowered"));
        let (b, note) = budget_from(Some("1e6"));
        assert_eq!(b, HEADROOM_BUDGET);
        assert!(note.unwrap().contains("not a number"));
        assert_eq!(budget_from(Some("900000")).0, HEADROOM_BUDGET);
    }

    #[test]
    fn the_kernel_keeps_fifteen_bytes_of_a_name() {
        assert_eq!(kernel_name("fim_file_open_sensor"), "fim_file_open_s");
        assert_eq!(kernel_name("exec_check_lsm"), "exec_check_lsm");
        assert_eq!(kernel_name("execpol_env_commit"), "execpol_env_com");
        assert_eq!(kernel_name("abcdefghijklmno"), "abcdefghijklmno");
    }

    #[test]
    fn the_kprobe_reads_the_count_and_the_name_through_the_verifier_state() {
        let o = ProbeOffsets {
            insn_processed: 0x2140,
            prog: 0,
            aux: 56,
            name: 520,
            tag: 24,
        };
        assert_eq!(
            kprobe_definition(
                "nn_verifier_check",
                "insn_processed",
                "check_max_stack_depth",
                "$arg1",
                o
            ),
            "p:nn_verifier_check/insn_processed check_max_stack_depth \
             insn=+8512($arg1):u32 tag=+24(+0($arg1)):x64 \
             name=+520(+56(+0($arg1))):string"
        );
    }

    /// The trace lines as the kernel prints them (5.15's format): the last
    /// line naming the program is its load's; other programs' lines, and
    /// header comments, are not.
    #[test]
    fn the_count_of_a_load_is_read_from_its_trace_line() {
        // the tags as the program info gives them (aya: big-endian) and as
        // the probe prints them (this machine's order)
        let (t1, t2, t3) = (0x3e1f_0011_2233_4455u64, 0x0102_0304_0506_0708u64, 0xaau64);
        let line = |n: u32, t: u64, name: &str| {
            format!(
                "northnarrow-age-4242 [001] d..1. 120.1: insn_processed: \
                 (check_max_stack_depth+0x0/0x2b0) insn={n} tag={:#x} name=\"{name}\"\n",
                probe_tag(t)
            )
        };
        let trace = format!(
            "# tracer: nop\n#\n{}{}{}",
            line(12, 0x99, "aya_name_check"),
            line(821_228, t1, "fim_file_open_s"),
            line(930_372, t2, "exec_check_lsm")
        );
        assert_eq!(
            count_in_trace(&trace, "fim_file_open_sensor", t1),
            Some(821_228)
        );
        assert_eq!(count_in_trace(&trace, "exec_check_lsm", t2), Some(930_372));
        assert_eq!(count_in_trace(&trace, "exec_env_lsm", t3), None);
        assert_eq!(count_in_trace("", "exec_check_lsm", t2), None);
        // the name alone is not enough: another tag is another program
        assert_eq!(count_in_trace(&trace, "exec_check_lsm", t1), None);
        assert_eq!(
            parse_trace_line("x: insn=7 tag=0x1f name=\"a b\""),
            Some((7, 0x1f, "a b"))
        );
        assert_eq!(parse_trace_line("x: insn= tag=0x1 name=\"a\""), None);
        assert_eq!(parse_trace_line("x: insn=7 tag=0x1 name=a"), None);
        assert_eq!(parse_trace_line("x: insn=7 name=\"a\""), None, "no tag");
        assert_eq!(parse_trace_line("x: insn=7 tag=0xz name=\"a\""), None);
        assert_eq!(
            parse_trace_line("x: insn=99999999999 tag=0x1 name=\"a\""),
            None
        );
        // two loads of one program in one buffer: the last is this load's
        let twice = format!("{}{}", line(5, t3, "p"), line(9, t3, "p"));
        assert_eq!(count_in_trace(&twice, "p", t3), Some(9));
        // the probe prints the program info's eight bytes in this
        // machine's order
        assert_eq!(probe_tag(t2).to_ne_bytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// The review of #551 (F3): two of the agent's programs share their 15
    /// bytes (`dns_answer_v4_ret4`, `dns_answer_v4_ret5`: the kernel keeps
    /// `dns_answer_v4_r`), and a foreign loader's program can too. Each
    /// load's count is the line with its own tag, whichever order the
    /// lines come in; a line with the name and another tag is never taken.
    #[test]
    fn programs_sharing_fifteen_bytes_are_told_apart_by_their_tag() {
        assert_eq!(
            kernel_name("dns_answer_v4_ret4"),
            kernel_name("dns_answer_v4_ret5")
        );
        let (r4, r5, foreign) = (0x1111u64, 0x2222u64, 0x3333u64);
        let l = |n: u32, t: u64| {
            format!(
                "a: insn={n} tag={:#x} name=\"dns_answer_v4_r\"\n",
                probe_tag(t)
            )
        };
        let trace = format!("{}{}{}", l(400, r4), l(500, r5), l(999_999, foreign));
        assert_eq!(count_in_trace(&trace, "dns_answer_v4_ret4", r4), Some(400));
        assert_eq!(count_in_trace(&trace, "dns_answer_v4_ret5", r5), Some(500));
        let only_foreign = l(999_999, foreign);
        assert_eq!(
            count_in_trace(&only_foreign, "dns_answer_v4_ret4", r4),
            None
        );
    }

    /// A program over the budget fails the kernel, and so does one the gate
    /// could not measure; the program info's count is preferred to the
    /// kprobe's, and both are compared where both exist.
    #[test]
    fn the_gate_fails_a_program_over_the_budget_or_unmeasured() {
        let ok = [
            m("a", Some(100), None),
            m("b", None, Some(899_999)),
            m("c", Some(900_000), Some(900_000)),
        ];
        let v = judge(&ok, HEADROOM_BUDGET);
        assert!(v.passes(), "{v:?}");
        assert_eq!(v.ranked[0], ("c".into(), 900_000, Source::Info));
        assert_eq!(v.ranked[1], ("b".into(), 899_999, Source::Kprobe));
        assert_eq!(v.cross_checked, 1);
        assert!(v.disagree.is_empty());
        assert!(verdict_line("5.15", &v).starts_with("== verifier headroom 5.15: OK"));

        let over = [m("a", Some(100), None), m("big", None, Some(900_001))];
        let v = judge(&over, HEADROOM_BUDGET);
        assert!(!v.passes());
        assert_eq!(v.over, vec![("big".to_string(), 900_001)]);
        let line = verdict_line("5.15", &v);
        assert!(
            line.starts_with("== verifier headroom 5.15: FAIL"),
            "{line}"
        );
        assert!(line.contains("big 900001"), "{line}");

        let blind = [m("a", Some(100), None), m("dark", None, None)];
        let v = judge(&blind, HEADROOM_BUDGET);
        assert!(!v.passes());
        assert_eq!(v.unmeasured, vec!["dark".to_string()]);
        assert!(verdict_line("5.15", &v).contains("unmeasured"));

        // the program info wins; a disagreement is reported
        let both = [m("x", Some(10), Some(11))];
        let v = judge(&both, HEADROOM_BUDGET);
        assert_eq!(v.ranked[0].1, 10);
        assert_eq!(v.disagree, vec![("x".to_string(), 10, 11)]);
        assert!(v.passes());

        // a lowered budget
        let v = judge(&[m("a", Some(600_001), None)], 600_000);
        assert!(!v.passes());
        assert!(verdict_line("k", &v).contains("over the budget 600000"));
    }

    #[test]
    fn the_report_ranks_the_top_ten() {
        let progs: Vec<Measured> = (1..=12u32)
            .map(|i| m(&format!("p{i:02}"), Some(i * 1000), None))
            .collect();
        let v = judge(&progs, HEADROOM_BUDGET);
        let r = report("6.8", &v);
        let rows: Vec<&String> = r.iter().filter(|l| l.starts_with("| ")).collect();
        // header + 10 rows
        assert_eq!(rows.len(), 1 + TOP, "{r:#?}");
        assert!(rows[1].starts_with("| 1 | p12 | 12000 | 1.3% | program info |"));
        assert!(rows[10].starts_with("| 10 | p03 | 3000 |"));
        assert_eq!(r.last().unwrap(), &verdict_line("6.8", &v));
        // lot 1.1 (F8b-1, P3): the share of the 900k gate, not of the
        // kernel's million — 5.15's sb_mount at rc4 read 83.1 % of the limit
        assert_eq!(share_of_gate(830_908), "92.3%");
        assert_eq!(share_of_gate(900_000), "100.0%");
        assert_eq!(share_of_gate(1_000_000), "111.1%");
        assert_eq!(share_of_gate(0), "0.0%");
        // rounded to the nearest tenth, not cut: 5.15's move_mount stage at
        // lot 1.1 is 51.075 % of the gate
        assert_eq!(share_of_gate(459_673), "51.1%");
        assert_eq!(share_of_gate(449_955), "50.0%");
        assert!(
            r.iter().any(|l| l.contains("| of the 900k gate |")),
            "{r:#?}"
        );
    }
}
