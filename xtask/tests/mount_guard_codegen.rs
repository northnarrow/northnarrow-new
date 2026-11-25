//! The review of #567 (lot 357's fix round): the mount guard's allow-list
//! check stays out of line in the eBPF object. Inlined into `decide`, the
//! BPF back end specialised its loop by the point's depth and, on the lab's
//! Ubuntu 22.04 guest (5.15), no kernel's own mount matched any more:
//! fusectl, configfs, binfmt_misc and tracefs mounted back, a chroot's
//! cgroup2, systemd-nspawn's and podman's own mounts were all refused. As
//! its own function (as lot 357 first shipped it) it matches; this keeps it
//! so.

use std::path::Path;

fn source(rel: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn the_allow_list_check_is_never_inlined_into_the_decision() {
    let s = source("common/src/mount_guard.rs");
    let at = s
        .find("pub fn allowed_kernel_mount(")
        .expect("allowed_kernel_mount is gone: keep the allow-list check out of line");
    let before = &s[..at];
    let attr = before.trim_end().lines().last().unwrap_or("");
    assert_eq!(
        attr.trim(),
        "#[inline(never)]",
        "allowed_kernel_mount must be #[inline(never)] (the eBPF allow-list miscompiled inlined)"
    );
}

/// The re-check 2 of #567 (N3): `sb_umount` reads the subtree an unmount
/// takes — `mount --rbind /sys /mnt/s; umount -l /mnt/s` judged the top
/// only (a copy, at a place nothing is held at) while the kernel took the
/// host's `/sys/fs/bpf` and `/sys/fs/cgroup` through the copies below it,
/// in every slave namespace too: the bpffs lost its last mount. The walk
/// (`common::mount_guard::umount_below`, its host tests the probes'
/// graphs) runs first, out of line (`subtree_takes`, its place look-up
/// `held_at`: inlined, 5.15's verifier went past its million instructions
/// and the call chain past 512 bytes of stack), its verdict folded into
/// the unmount's before the top is judged.
#[test]
fn an_unmount_is_judged_by_the_subtree_it_takes() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let at = e
        .find("unsafe fn try_sb_umount(")
        .expect("try_sb_umount is gone");
    let hook = &e[at..];
    let hook = &hook[..hook.find("\n}\n").expect("its end")];
    let walk = hook
        .find("let below = subtree_takes(o, real) != 0;")
        .expect("the subtree is not read");
    let top = hook
        .find("if guard != 0 && !q.held {")
        .expect("the top's own check");
    assert!(walk < top, "the walk is folded in before the top");
    assert!(hook.contains("if below {\n            q.held = true;"));
    for (f, sig) in [
        (
            "subtree_takes",
            "fn subtree_takes(o: &Offs, real: *const u8) -> u64 {",
        ),
        (
            "held_at",
            "unsafe fn held_at(o: &Offs, m: *const u8, group: u32) -> u64 {",
        ),
    ] {
        let at = e.find(sig).unwrap_or_else(|| panic!("{f} is gone"));
        let attr = e[..at].trim_end().lines().last().unwrap_or("");
        assert_eq!(attr.trim(), "#[inline(never)]", "{f} must stay out of line");
    }
    let walker = &e[e.find("fn subtree_takes(").unwrap()..];
    assert!(
        walker[..walker.find("\n}\n").unwrap()]
            .contains("below_takes_held(umount_below(&Subtree { o, by_id }, real), by_id != 0)")
    );
    // the tree read is the kernel's: the children and the siblings' links
    let tree = &e[e.find("impl Tree for Subtree").expect("the kernel's tree")..];
    for f in ["o.mnt_mounts", "o.mnt_child", "o.mnt_parent", "below_of("] {
        assert!(tree.contains(f), "{f}");
    }
    // no sixteen-byte array to zero in the place's name: a `memset` call
    let name = &e[e.find("unsafe fn name_of(").unwrap()..];
    let name = &name[..name.find("\n}\n").unwrap()];
    assert!(!name.contains("[0u8; 16]") && name.contains("crate::zero::zero("));
    let c = source("common/src/mount_guard.rs");
    assert!(c.contains("pub const SUBTREE_MAX: u32 = 32;"));
}

/// Lot 359 (the re-check 3 of #567, N4): the judge of a change of
/// propagation that reaches the pin directory's lock is out of line and
/// calls nothing that carries a frame of its own — no `decide` (its
/// allow-list call), no record (the ring entry's zeroing call): the lab's
/// first verifier check refused `sb_mount` on 6.8, its chain 576 bytes of
/// 512. It returns the verdict; the hook signs it in its own frame.
#[test]
fn the_lock_judge_is_out_of_line_and_signs_nothing() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let at = e
        .find("fn lock_propagation(path: *const u8, flags: u64) -> u64 {")
        .expect("lock_propagation is gone");
    let attr = e[..at].trim_end().lines().last().unwrap_or("");
    assert_eq!(attr.trim(), "#[inline(never)]");
    let t = e
        .find("unsafe fn try_lock_propagation(")
        .expect("try_lock_propagation is gone");
    let body = &e[t..];
    let body = &body[..body.find("\n}\n").expect("its end")];
    for call in [
        "decide(",
        "answer(",
        "answer_parts(",
        "emit_attempt(",
        "Query {",
        "query(",
    ] {
        assert!(!body.contains(call), "the out-of-line judge calls {call}");
    }
    assert!(body.contains("lock_verdict("));
    // lot 1.1 (F8b-1): in `sb_mount`'s propagation stage
    let hook = &e[e.find("unsafe fn try_sb_mount_propagate(").unwrap()..];
    let hook = &hook[..hook.find("\n}\n").unwrap()];
    assert!(hook.contains("let r = lock_propagation(path, flags);"));
    assert!(hook.contains("lock_answer(path, r)"));
}

/// The review of #569 (F1a, F1c): the lock's judge in `sb_mount` reads the
/// namespace before the rule — a recursive `MS_PRIVATE` or `MS_SHARED`
/// above the lock (the re-check of #569, N1) is judged only where the
/// mount changed is PID 1's (`lock_touched` with the
/// target's guard, after `target_of`), the maker's identity is asked only
/// of its own step on the host's lock (`lock_step_at`, never `lock_step`
/// alone), and `systemd-shutdown`'s identity only of its `switch_root()`
/// shape (`lock_shutdown_step`).
#[test]
fn the_lock_judge_reads_the_namespace_before_a_private_change_and_the_makers_step() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let t = e
        .find("unsafe fn try_lock_propagation(")
        .expect("try_lock_propagation is gone");
    let body = &e[t..];
    let body = &body[..body.find("\n}\n").expect("its end")];
    let widest = body
        .find("lock_touched(flags, on_lock, above, GUARD_HOST)")
        .expect("the widest rule first");
    let target = body.find("target_of(o, at)").expect("the target's guard");
    let by_ns = body
        .find("lock_touched(flags, on_lock, above, guard)")
        .expect("the rule by the target's namespace");
    assert!(widest < target && target < by_ns, "the order of the rule");
    // lot 1.1 (F8b-1): the maker and the shutdown asked of their global
    // functions (`nn_mount_lock_maker`, `nn_mount_shutdown_stage`)
    assert!(body.contains("lock_step_at(flags, on_lock, guard) && nn_mount_lock_maker() != 0"));
    assert!(body.contains("lock_shutdown_step(flags, on_lock) && nn_mount_shutdown_stage() != 0"));
    assert!(
        !body.contains("lock_step(flags)"),
        "the maker's step anywhere"
    );
}

/// The review of #569's fix round (lab, 5.15): `spread`'s slave carried
/// across its loop as an `Option<G::M>` started as `None`, whose payload is
/// never written — the BPF back end loaded it before it tested the tag
/// (a select), and 5.15's verifier refused `sb_mount` ("invalid read from
/// stack"; 6.5 and later allow the read for a privileged loader, so 6.8
/// and 7.0 loaded it). The walks the eBPF inlines carry no `Option` in a
/// mutable binding: a value always written, and a flag.
/// The `let mut` bindings of `code` (its tests left out) that carry an
/// `Option` across a loop: written with the type (`: Option<`), started
/// as `None`, `None::<T>` anywhere, or — lot 1.1 (the re-check 1 of #569,
/// a P3) — inferred from a walk step that returns one (`first_slave`,
/// `next_slave`, `next_peer`, `first_child`, `next_sibling`) or from
/// `Some(`.
fn option_carriers(code: &str) -> Vec<String> {
    let code = &code[..code.find("#[cfg(test)]").unwrap_or(code.len())];
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        let binding = t.starts_with("let mut ");
        let init = t.split_once('=').map(|x| x.1.trim()).unwrap_or("");
        let inferred = binding
            && ([
                ".first_slave(",
                ".next_slave(",
                ".next_peer(",
                ".first_child(",
                ".next_sibling(",
            ]
            .iter()
            .any(|f| init.contains(f))
                || init.starts_with("Some("));
        if (binding && t.contains(": Option<"))
            || (binding && t.ends_with("= None;"))
            || t.contains("None::<")
            || inferred
        {
            out.push(format!("{}: {t}", n + 1));
        }
    }
    out
}

#[test]
fn the_mount_walks_carry_no_option_across_a_loop() {
    for rel in ["common/src/mount_guard.rs", "agent-ebpf/src/mount_guard.rs"] {
        let found = option_carriers(&source(rel));
        assert!(found.is_empty(), "{rel}: a mutable Option: {found:?}");
    }
    // each shape is seen (planted)
    for planted in [
        "let mut s: Option<u32> = x;",
        "let mut s = None;",
        "let s = None::<u32>;",
        "let mut s = g.first_slave(p);",
        "let mut s = t.next_sibling(m);",
        "let mut s = Some(m);",
    ] {
        assert_eq!(option_carriers(planted).len(), 1, "{planted}");
    }
    assert!(option_carriers("let mut i = 0;\nlet s = g.first_slave(p);").is_empty());
}

/// Lot 1.1 (F8b-1): `sb_mount` and `move_mount` are an entry and stages —
/// the entry tail-calls its stage once the target lands in a guarded
/// namespace (or for a change of propagation), from the hook's own body
/// (an `#[inline(always)]` function: a tail call from a BPF-to-BPF callee
/// would put its frames' stack under 256 bytes on x86), and counts a tail
/// call that returns (an empty slot) as a fail-open; the judge (`decide`,
/// the point's walk, the answer) is in the stages only, which tail-call
/// nothing. The walk to the target stays out of line (`lands_guarded`).
#[test]
fn the_split_hooks_judge_in_their_stages() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let body = |sig: &str| -> String {
        let at = e.find(sig).unwrap_or_else(|| panic!("{sig} is gone"));
        let attr = e[..at].trim_end().lines().last().unwrap_or("");
        assert_eq!(attr.trim(), "#[inline(always)]", "{sig}");
        let b = &e[at..];
        b[..b.find("\n}\n").expect("its end")].to_string()
    };
    // the judge of where a mount lands is a stage's; `move_mount`'s entry
    // judges the source (a held mount, or a peer copy of one, moved away)
    let landing = ["point_of(", "string_key(", "fstype_of(", "lock_bind("];
    for (entry, array, hook, slots, judges) in [
        (
            "unsafe fn try_sb_mount(",
            "MOUNT_SB_STAGES",
            "SB_MOUNT",
            &["STAGE_PROPAGATE", "STAGE_POINT"][..],
            &[
                "decide(",
                "decide_as(",
                "decide_code(",
                "decide_out_of_line(",
                "answer(",
                "lock_propagation(",
            ][..],
        ),
        (
            "unsafe fn try_move_mount(",
            "MOUNT_MOVE_STAGES",
            "MOVE_MOUNT",
            &["STAGE_POINT"][..],
            &[][..],
        ),
    ] {
        let b = body(entry);
        for slot in slots {
            let call = format!("{array}.tail_call(ctx, {slot});");
            let at = b.find(&call).unwrap_or_else(|| panic!("{entry}: {call}"));
            let next = b[at + call.len()..]
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with("//"))
                .unwrap_or("");
            assert_eq!(
                next,
                format!("crate::fail_open::bump(hook::{hook});"),
                "{entry}: a tail call that returns is not counted"
            );
        }
        for judge in landing.iter().chain(judges) {
            assert!(
                !b.contains(judge),
                "{entry} judges ({judge}): its stage does"
            );
        }
        assert!(
            b.contains("lands_guarded(o, "),
            "{entry}: the walk to the target"
        );
    }
    for stage in [
        "unsafe fn try_sb_mount_point(",
        "unsafe fn try_sb_mount_propagate(",
        "unsafe fn try_move_mount_point(",
    ] {
        let b = body(stage);
        assert!(!b.contains("tail_call("), "{stage} tail-calls");
    }
    for (program, hook) in [
        ("mount_guard_sb_mount_point", "sb_mount"),
        ("mount_guard_sb_mount_propagate", "sb_mount"),
        ("mount_guard_move_mount_point", "move_mount"),
    ] {
        assert!(
            e.contains(&format!(
                "#[lsm(hook = \"{hook}\")]\npub fn {program}(ctx: LsmContext)"
            )),
            "{program}"
        );
    }
    let at = e
        .find("fn lands_guarded(o: &Offs, real: *const u8) -> u64 {")
        .expect("lands_guarded is gone");
    assert_eq!(
        e[..at].trim_end().lines().last().unwrap_or("").trim(),
        "#[inline(never)]"
    );
    // the userland loads every stage before its entry
    let u = source("crates/nn-linux/src/anti_tamper/mount_guard.rs");
    for (program, _) in [
        ("mount_guard_sb_mount_point", ()),
        ("mount_guard_sb_mount_propagate", ()),
        ("mount_guard_move_mount_point", ()),
    ] {
        assert!(
            u.contains(&format!("\"{program}\"")),
            "{program} not loaded"
        );
    }
    let attach = &u[u.find("pub(crate) fn attach(").expect("attach")..];
    let stages = attach
        .find("load_stages(ebpf, hook, btf)")
        .expect("the stages loaded");
    let entry = attach
        .find("load_lsm(ebpf, program, hook, btf, pin_root)")
        .expect("the entry");
    assert!(stages < entry, "an entry attached before its stages");
}

/// Lot 1.1 (the re-check 2 of #569, N3): the agent's and the watchdog's
/// namespaces are guarded as theirs only when they are not PID 1's — both
/// writers ask `guards_own_namespace` before `set_guarded`, and the eBPF
/// `vacate` never drops PID 1's.
#[test]
fn a_roles_namespace_never_takes_pid_1s_entry() {
    let u = source("crates/nn-linux/src/anti_tamper/mount_guard.rs");
    for f in [
        "pub(crate) fn guard_own_namespace(",
        "pub fn guard_watchdog(",
    ] {
        let b = &u[u.find(f).unwrap_or_else(|| panic!("{f} is gone"))..];
        let b = &b[..b.find("\n}\n").expect("its end")];
        let ask = b
            .find("guards_own_namespace(inum, ")
            .unwrap_or_else(|| panic!("{f} does not ask"));
        let set = b
            .find("set_guarded(&mut nm, inum, ")
            .unwrap_or_else(|| panic!("{f} sets nothing"));
        assert!(ask < set, "{f}: set before asked");
    }
    let e = source("agent-ebpf/src/mount_guard.rs");
    let v = &e[e.find("pub(crate) fn vacate(").expect("vacate")..];
    let v = &v[..v.find("\n}\n").unwrap()];
    assert!(
        v.contains("if vacates(inum, host) {"),
        "vacate drops any namespace"
    );
}

/// Lot 1.1 (F8b-1): every hook decides with its operation a constant of
/// its own (`decide_code(MG_OP_…, &q)`, or `decide_out_of_line(MG_OP_…,
/// &q)` in `sb_mount`'s point stage — the literal its query was made
/// with), never through `decide(&q)`, whose `q.op` 5.15's verifier reads as
/// any byte and explores every arm for; and every answer is signed from a
/// number (`verdict_code`), never a `Verdict` whose `Allow` has an
/// undefined payload byte.
#[test]
fn the_hooks_decide_with_their_operation_a_constant() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    assert!(!e.contains("decide(&q)"), "a hook decides through q.op");
    assert!(!e.contains("decide_as("), "a Verdict through the hook");
    let mut n = 0;
    for call in ["decide_code(", "decide_out_of_line("] {
        let mut from = 0;
        while let Some(at) = e[from..].find(call) {
            let at = from + at;
            from = at + 1;
            // the definition, and the out-of-line wrapper's own call
            if e[..at].ends_with("fn ") || e[at..].starts_with("decide_code(op, q)") {
                continue;
            }
            let rest = &e[at + call.len()..];
            let op = &rest[..rest.find(',').expect("its operation")];
            assert!(
                op.starts_with("MG_OP_"),
                "{call}{op}, …): not a literal operation"
            );
            // the function it is in made its query with that operation
            let start = e[..at]
                .rfind("\nunsafe fn ")
                .max(e[..at].rfind("\nfn "))
                .expect("its function");
            let body = &e[start..at];
            assert!(
                body.contains(&format!("query({op}, ")) || body.contains(&format!("q.op = {op};")),
                "{call}{op}, …) in a function whose query is another operation's"
            );
            n += 1;
        }
    }
    assert!(n >= 8, "{n} decisions");
    let a = &e[e.find("fn answer_parts(").expect("answer_parts")..];
    let a = &a[..a.find("\n}\n").unwrap()];
    assert!(
        a.starts_with("fn answer_parts(code: u16,"),
        "an answer from a Verdict"
    );
    let c = source("common/src/mount_guard.rs");
    assert!(c.contains("pub fn decide(q: &Query) -> Verdict {\n    decide_as(q.op, q)\n}"));
}
